"""Utility classes for working with parsed ZMD output."""

import collections.abc
import itertools
import re
from typing import Iterator, Mapping, Match, Optional, Union

from .errors import ZmdSyntaxError
from .raw_zmd_schema import NAME, POSITIVE_INTEGER, PRIMITIVE_TYPES


class ZmdFieldType:
    """Utility class which parses a ZMD type expression.

    Example expressions:

        Scalars:
            MyType
            packed MyType

        Arrays:
            MyType[10]
            MyType[MY_SIZE]
            packed MyType[10]
            packed MyType[MY_SIZE]

        Vectors:
            MyType[<=10]
            MyType[<=MY_SIZE]
    """

    TYPE_PAT = re.compile(
        rf"""^
        ((?P<is_packed>packed)\ )? # Optional 'packed' keyword.

        (?P<type_name>{NAME})      # Base type name.

        (?P<is_arraylike>\[        # Type may be followed by brackets to signify an array or vector.
            (?P<is_vector><=)?     # <= 'emotivec' syntax indicates a vector.
            ((?P<literal_size>{POSITIVE_INTEGER})|(?P<named_size>{NAME}))
        \])?$
    """,
        re.VERBOSE,
    )

    def __init__(self, type_expression: str):
        """Parses the given expression. Raises ZmdSyntaxError if the expression is invalid."""
        expression = self.TYPE_PAT.match(type_expression)
        if expression is None:
            raise ZmdSyntaxError(f"Invalid type expression: {type_expression}")
        else:
            self._expression: Match[str] = expression

    @property
    def name(self) -> str:
        return self._expression.group("type_name")

    @property
    def is_packed(self) -> bool:
        return self._expression.group("is_packed") is not None

    @property
    def is_scalar(self) -> bool:
        return self._expression.group("is_arraylike") is None

    @property
    def is_vector(self) -> bool:
        return self._expression.group("is_vector") is not None

    @property
    def is_array(self) -> bool:
        return (not self.is_scalar) and (not self.is_vector)

    @property
    def has_named_size(self) -> bool:
        """Returns true if the type is not scalar, and the size is a symbol name rather than a literal."""
        return isinstance(self.size, str)

    @property
    def size(self) -> Optional[Union[str, int]]:
        """For array or vector types, returns the literal size or size name. Otherwise returns None."""
        if self._expression.group("literal_size") is not None:
            return int(self._expression.group("literal_size"))
        elif self._expression.group("named_size") is not None:
            return self._expression.group("named_size")
        else:
            return None


class ZmdNode(collections.abc.Mapping):
    """Utility class for parsed output that provides some more convenient accessors and iterators.

    Specifically, any dict in the parsed output containing a "name" or "was" key can be wrapped in a ZmdNode.

    This is most useful for working with structs and struct fields.

    Example usage:

        parsed = parse(zmd_text)
        for struct_name, struct_definition in parsed["structs"].items():
            struct = ZmdNode(struct_definition)

            # Iterate over all struct members recursively (expanding unions and bitfields):
            for field in struct.flat_fields():
                print(field.field_type().name)

            # Shallow iteration over struct members:
            for field in struct.fields():
                if "bitfield" in field:
                    print(field.bits())

            # List all named sizes used in the struct definition:
            for size_name in struct.referenced_sizes():
                print(size_name)

            # Use the ZmdNode like a normal mapping:
            print(struct["name"])
    """

    def __init__(self, value: Mapping):
        self._value = value

    def __getitem__(self, key):
        return self._value[key]

    def __iter__(self):
        return iter(self._value)

    def __len__(self):
        return len(self._value)

    def __eq__(self, other):
        return self._value == other

    def __repr__(self):
        return repr(self._value)

    def fields(self) -> Iterator["ZmdNode"]:
        """Iterate over the node's field-like members, without recursing into sub-fields.

        Returns an empty iterator if the node is not a struct, union, or bitfield, or does not contain fields.
        """
        if "fields" in self:
            for field in self["fields"]:
                yield ZmdNode(field)

        elif "union" in self:
            for field in self["union"]:
                yield ZmdNode(field)

        elif "bitfield" in self:
            for field in self["bitfield"]:
                yield ZmdNode(field)

    def flat_fields(self, exclude_bitfields=False) -> Iterator["ZmdNode"]:
        """Recursively iterate over all the node's field-like descendants.

        On the wire, bitfields are an array of u8. Therefore, bitfields are not expanded.

        Returns an empty iterator if the node is not a struct, union, or bitfield, or does not contain fields.
        """
        for field in self.fields():
            if "union" in field:
                for subfield in field.fields():
                    # Unions can have bitfields in them.
                    if "bitfield" in subfield:
                        if exclude_bitfields:
                            continue
                        for bitfield in subfield.fields():
                            yield bitfield
                    else:
                        yield subfield
            elif "bitfield" in field:
                if exclude_bitfields:
                    continue

                yield field
            else:
                yield field

    def field_type(self) -> ZmdFieldType:
        """If the node represents a struct or union field, returns the parsed type.

        Raises:
            KeyError if the node is not a struct/union field.
        """
        return ZmdFieldType(self["type"])

    def bits(self) -> Iterator["ZmdNode"]:
        """If the node represents a bitfield, returns the list of parsed bits.

        Raises:
            KeyError if the node is not a bitfield.
        """
        for bit in self.get("bitfield", []):
            yield ZmdNode(bit)

    def referenced_types(self) -> Iterator[str]:
        """If the node contains fields, returns a list of all non-primitive type names referenced by the fields.

        The list may contain duplicates.

        Returns an empty iterator if the node is not a struct, union, or bitfield, or does not contain fields.
        """
        for field in self.flat_fields(exclude_bitfields=True):
            type_name = field.field_type().name
            if type_name not in PRIMITIVE_TYPES:
                yield type_name

    def referenced_sizes(self) -> Iterator[str]:
        """If the node contains fields, returns a list of all named array/vector sizes referenced by the fields.

        The list may contain duplicates.

        Returns an empty iterator if the node is not a struct, union, or bitfield, or does not contain fields.
        """
        for field in self.flat_fields(exclude_bitfields=True):
            field_type = field.field_type()
            if isinstance(field_type.size, str):
                yield field_type.size
