"""This module makes it possible to interpret "zipline message" data based purely on annotations provided at runtime.

The interface is based around built-in python data structures. Structs are represented as mappings of string field
names to values. Enums are represented as their string names, or integer values if the name isn't known. In order to
make this approach more manageable, special wrappers are used to make the data structure keys only safely mutable.

Example, loading from annotations:

    from tools.messages import runtime_zipline_message

    annotations = '''
    enum SomeEnum2 (was SomeEnum):
    FOO: 0
    BAR: 2

    struct Test:
    - foo: SomeEnum2
    '''
    rzm = runtime_zipline_message.from_annotations(annotations)
    msg = rzm.create("Test")
    assert msg == {"foo": None}
    msg["foo"] = "BAR"
    assert msg == rzm.deserialize("Test", rzm.serialize("Test", msg))

The runtime zipline message implementation serves as the only implementation for python. ZMD files can be directly
loaded, using the `from_zmd` function.

Example, loading from a zmd file:

    from tools.messages import runtime_zipline_message

    BUILD_ROOT = os.path.join(os.path.dirname(__file__), "..", "..", "..")
    zmd = os.path.join(BUILD_ROOT, "lib", "zmd", "test", "test.zmd")
    rzm = runtime_zipline_message.from_zmd(zmd, BUILD_ROOT)
    msg = rzm.create("Test")
    msg["foo"] = 42
    assert msg == rzm.deserialize("Test", rzm.serialize("Test", msg))
"""
# ruff: noqa: ANN401

import io
import struct
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from collections.abc import Mapping as AbcMapping
from pathlib import Path
from typing import Any

# Modules in the same package must be locally imported
from . import (  # type: ignore[attr-defined]
    _python_packaging,
    media_types,
)

with _python_packaging.flight_systems_context():
    from .zmd.annotations import cull, dump, flatten, merge_named_zmds
    from .zmd.parse import parse
    from .zmd.parser_types import ParsedZmd
    from .zmd.util import ZmdNode


# mypy complains about ByteString going into struct.unpack, so we'll make our own.
BufferType = bytes | bytearray | memoryview

# TODO: Let's move this version info somewhere centralized eventually
# Note: This module needs to support all past schema versions.
MAX_SCHEMA_VERSION = 0


# Constants used by the FNV-1a hash algorithm
FNV_32BIT_OFFSET_BASIS = 2166136261
FNV_32BIT_PRIME = 16777619

MAX_FRAME_SIZE = 255
MAX_JUMBO_FRAME_SIZE = 16777215


def field_hash(name: str, typename: str) -> int:
    """Computes the hash value for a field based on its name and typename."""
    hash_value = FNV_32BIT_OFFSET_BASIS
    for b in b"\0".join([name.encode(), typename.encode(), b""]):
        hash_value ^= b
        hash_value *= FNV_32BIT_PRIME
        hash_value &= 0xFFFFFFFF
    return (hash_value & 0xFFFF) ^ (hash_value >> 16)


# Used to work with the header in the wire format.
#   data_size (1 byte): The size of the data, or 0xFF if a jumbo frame
#   hash_value_or_data_size (2 bytes): The hash value of the data,
#       or the bottom 16 bits of frame size if a jumbo frame
_HEADER_STRUCT = struct.Struct("<BH")


# Built-in types mapped to a corresponding struct object.
_BUILTIN_TYPES = {
    "bool": struct.Struct("<?"),
    "f32": struct.Struct("<f"),
    "f64": struct.Struct("<d"),
    "u8": struct.Struct("<B"),
    "u16": struct.Struct("<H"),
    "u32": struct.Struct("<I"),
    "u64": struct.Struct("<Q"),
    "i8": struct.Struct("<b"),
    "i16": struct.Struct("<h"),
    "i32": struct.Struct("<i"),
    "i64": struct.Struct("<q"),
}


class UnsupportedSchemaVersion(ValueError):  # noqa: N818
    """Raised if the message schema version is unsupported."""


class _StructMapping(AbcMapping):
    """A dict-like mapping that has fixed keys."""

    __slots__ = ["_data"]

    def __init__(self, fields: dict[str, Any]) -> None:
        super().__init__()
        self._data = fields

    def __repr__(self) -> str:
        return repr(self._data)

    def __str__(self) -> str:
        return str(self._data)

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __setitem__(self, key: str, value: Any) -> None:
        if key not in self._data:
            raise KeyError
        self._data[key] = value

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)


class _UnionMapping(AbcMapping):
    """A dict-like mapping that can only hold one key-value at a time, out of a fixed set of keys.

    The fields have a default value factory, which is accessible through the special select method.
    """

    __slots__ = ["_contains", "_fields"]

    def __init__(self) -> None:
        super().__init__()
        self._fields: dict[str, Callable[[], Any]] = {}
        self._contains: tuple[str, Any] | None = None

    def __repr__(self) -> str:
        return repr(dict(self))

    def __str__(self) -> str:
        return str(dict(self))

    def add_field(self, key: str, default_value_factory: Callable[[], Any]) -> None:
        """Adds a field to the union.

        The default_value_factory will be called if select() is used.
        """
        self._fields[key] = default_value_factory

    def clear(self) -> None:
        self._contains = None

    def select(self, key: str) -> None:
        if key not in self._fields:
            raise ValueError
        if self._contains is None or self._contains[0] != key:
            self._contains = (key, self._fields[key]())

    def __delitem__(self, key: str) -> None:
        if key not in self:
            raise KeyError
        self._contains = None

    def __getitem__(self, key: str) -> Any:
        if self._contains is None or self._contains[0] != key:
            raise KeyError
        return self._contains[1]

    def __setitem__(self, key: str, value: Any) -> None:
        if key not in self._fields:
            raise KeyError
        self._contains = (key, value)

    def __iter__(self) -> Iterator[str]:
        if self._contains is not None:
            yield self._contains[0]

    def __len__(self) -> int:
        return 0 if self._contains is None else 1


class _ValueObject(ABC):
    """A base class to make type hints happy.

    _ValueObjects know how to manipulate values within a field.
      They're used in conjunction with Field objects.
    """

    __slots__: list[str] = []

    @abstractmethod
    def default_value(self) -> Any:
        """Returns a sane default value, such as 0, False, an empty list, etc."""

    @abstractmethod
    def serialize_value(self, value: Any) -> list[bytes]:
        """Serializes the value into its wire encoding.

        Returns a list of frames to be written.
          The number of frames is variable, depending on whether it's a scalar,
        array, vector, etc.
        """

    @abstractmethod
    def deserialize_value(self, frames: list[BufferType]) -> Any:
        """Deserializes the value from its wire encoding."""


class RuntimeZiplineMessage:
    """A runtime message object for Zipline messages."""

    __slots__ = ["_fields_by_struct", "_parsed_zmd", "_reverse_enums"]

    def __init__(self, parsed_zmd: ParsedZmd) -> None:  # noqa: PLR0912
        """Initializes a RuntimeZiplineMessage for the given schema."""
        self._parsed_zmd = parsed_zmd
        # Pre-compute enum value name lookup
        self._reverse_enums = {
            e["name"]: dict(zip(e["values"].values(), e["values"].keys(), strict=False))
            for e in self._parsed_zmd["enums"].values()
        }
        # Pre-compute field objects for all struct fields, keyed by their hash.
        self._fields_by_struct: dict[str, dict[int, Any]] = {}
        for name, schema_struct in self._parsed_zmd["structs"].items():
            # TODO: Field ABC?
            fields: dict[int, Any] = {}
            for field in ZmdNode(schema_struct).fields():
                if "union" in field:
                    for union_field in field.fields():
                        if "name" not in union_field:
                            continue  # It was unnamed
                        hash_value = self._hash(union_field)
                        if hash_value in fields:
                            raise ValueError(f"Hash collision detected for {union_field['name']}")
                        fields[hash_value] = _UnionField(
                            field["name"],
                            union_field["name"],
                            self._value_object(union_field),
                        )
                    continue
                # Just a regular field
                if "name" not in field:
                    continue  # It was unnamed
                hash_value = self._hash(field)
                if hash_value in fields:
                    raise ValueError(f"Hash collision detected for {field['name']}")
                if "type" in field:
                    info = field.field_type()
                    if info.is_packed:
                        fields[hash_value] = _PackedField(field["name"], self._value_object(field))
                    elif info.is_vector:
                        fields[hash_value] = _VectorField(field["name"], self._value_object(field))
                    else:
                        fields[hash_value] = _OptionalField(
                            field["name"], self._value_object(field)
                        )
                else:
                    fields[hash_value] = _VectorField(field["name"], self._value_object(field))

            self._fields_by_struct[name] = fields

    def _hash(self, field: ZmdNode) -> int:
        """Computes the hash for a field."""
        if "type" in field:
            info = field.field_type()
            # Structs and enums could have been renamed.
            if info.name in self._parsed_zmd["structs"]:
                type_name = self._parsed_zmd["structs"][info.name].get("was", info.name)
            elif info.name in self._parsed_zmd["enums"]:
                type_name = self._parsed_zmd["enums"][info.name].get("was", info.name)
            else:
                type_name = info.name
        elif "bitfield" in field:
            type_name = "u8"
        else:
            raise RuntimeError
        return field_hash(field.get("was", field["name"]), type_name)

    def _value_object(self, field: ZmdNode) -> _ValueObject:  # noqa: PLR0911
        """Creates a value object for the given field."""
        if "type" in field:
            info = field.field_type()
            if info.is_scalar:
                if info.name in _BUILTIN_TYPES:
                    return _ScalarBuiltinValue(_BUILTIN_TYPES[info.name])
                if info.name in self._parsed_zmd["enums"]:
                    return _ScalarEnumValue(
                        self._parsed_zmd["enums"][info.name]["values"],
                        self._reverse_enums[info.name],
                    )
                return _ScalarStructValue(self, info.name)
            if info.size is None:
                raise RuntimeError(f"Field {field} has no size annotation")
            size = self._parsed_zmd["sizes"][info.size] if isinstance(info.size, str) else info.size
            if info.is_array:
                if info.name == "u8":
                    return _ArrayBytesValue(size)
                if info.name in _BUILTIN_TYPES:
                    return _ArrayBuiltinValue(size, _BUILTIN_TYPES[info.name])
                if info.name in self._parsed_zmd["enums"]:
                    return _ArrayEnumValue(
                        size,
                        self._parsed_zmd["enums"][info.name]["values"],
                        self._reverse_enums[info.name],
                    )
                return _ArrayStructValue(size, self, info.name)
            # It must be a vector.
            if info.name == "u8":
                return _VectorBytesValue(size)
            if info.name in _BUILTIN_TYPES:
                return _VectorBuiltinValue(size, _BUILTIN_TYPES[info.name])
            if info.name in self._parsed_zmd["enums"]:
                return _VectorEnumValue(
                    size,
                    self._parsed_zmd["enums"][info.name]["values"],
                    self._reverse_enums[info.name],
                )
            return _VectorStructValue(size, self, info.name)

        bits = {b["name"]: i for i, b in enumerate(field.bits()) if "name" in b}
        num_bytes = (max(bits.values()) + 8) // 8
        return _BitfieldValue(bits, num_bytes)

    def metadata(self, struct_name: str) -> bytes:
        """Creates a metadata payload for the given struct.

        Metadata payloads may be used with the message_from_metadata
          function in the messages package in order to subsequently serialize and deserialize data.
        Metadata payloads are what gets sent over Zip IPC and are stored in ZML.
        """
        return b"".join(
            [
                media_types.ZIPLINE_MESSAGE_MEDIA_TYPE,
                f"; schema_version={MAX_SCHEMA_VERSION}; struct={struct_name}\n".encode(),
                dump(cull(self._parsed_zmd, [struct_name])).encode("utf-8"),
            ]
        )

    def create(self, struct_name: str) -> _StructMapping:
        """Creates a new struct instance, with default values.

        Args:
            struct_name: The name of the struct to create.

        Returns the instance of the struct.
        """
        new_struct: dict[str, Any] = {}
        for field in self._fields_by_struct[struct_name].values():
            field.set_default(new_struct)
        return _StructMapping(new_struct)

    def serialize(self, struct_name: str, instance: Mapping) -> bytes:
        """Serializes the specified struct.

        Args:
            struct_name: The name of the struct to serialize.
            instance: The instance of the struct.

        Returns the serialized struct.
        """
        fragments = []
        for hash_value, field in self._fields_by_struct[struct_name].items():
            for frame_data in field.serialize(instance):
                data_size = len(frame_data)
                if data_size >= MAX_FRAME_SIZE:
                    if data_size >= MAX_JUMBO_FRAME_SIZE:
                        raise ValueError(f"Frame is too long to fit: {data_size}")
                    # Write a jumbo frame
                    fragments.append(_HEADER_STRUCT.pack(0xFF, data_size & 0xFFFF))
                    data_size >>= 16
                fragments.append(_HEADER_STRUCT.pack(data_size, hash_value))
                fragments.append(frame_data)
        return b"".join(fragments) or b"\0"  # Otherwise empty structs must be null padded.

    def deserialize(self, struct_name: str, data: BufferType) -> _StructMapping:
        """Deserializes the specified struct.

        Args:
            struct_name: The name of the struct to serialize.
            data: The serialized struct.

        Returns the deserialized struct.
        """
        # Separate out all the frames by hash, before trying to deserialize them.
        frames_by_hash: dict[int, list[BufferType]] = {}
        if data != b"\0":
            offset = 0
            while True:
                try:
                    data_size, hash_value = _HEADER_STRUCT.unpack_from(data, offset)
                    offset += _HEADER_STRUCT.size
                    if data_size == MAX_FRAME_SIZE:
                        # It's a jumbo frame
                        data_size = hash_value
                        upper_data_size, hash_value = _HEADER_STRUCT.unpack_from(data, offset)
                        data_size += upper_data_size << 16
                        offset += _HEADER_STRUCT.size
                except struct.error as e:
                    raise ValueError from e
                new_offset = offset + data_size
                frames_by_hash.setdefault(hash_value, []).append(data[offset:new_offset])
                if new_offset >= len(data):
                    if new_offset > len(data):
                        raise ValueError("Data frame is truncated")
                    break  # Done
                offset = new_offset
        # Now deserialize
        new_struct: dict[str, Any] = {}
        for hash_value, field in self._fields_by_struct[struct_name].items():
            field.deserialize(new_struct, frames_by_hash.get(hash_value, []))
        return _StructMapping(new_struct)


class _ScalarBuiltinValue(_ValueObject):
    """A scalar value consisting of a built-in type such as an integer, float, bool, etc."""

    __slots__ = ["packer"]

    def __init__(self, packer: struct.Struct) -> None:
        """Initializes the object to manipulate the value."""
        self.packer = packer

    def default_value(self) -> Any:
        return self.packer.unpack(b"\0" * self.packer.size)[0]

    def serialize_value(self, value: Any) -> list[bytes]:
        return [self.packer.pack(value)]

    def deserialize_value(self, frames: list[BufferType]) -> Any:
        if len(frames) != 1:
            raise ValueError(f"Expected one frame but got {len(frames)}")
        return self.packer.unpack(frames[0])[0]


class _ScalarEnumValue(_ValueObject):
    """A scalar value consisting of an enum as defined in the schema.

    Enum values are nominally a string name.
      If the name isn't known, though, the value will be its integer instead.
    """

    __slots__ = ["enum", "reverse_enum"]

    def __init__(self, enum: Mapping[str, int], reverse_enum: Mapping[int, str]) -> None:
        """Initializes the object to manipulate the value."""
        self.enum = enum
        self.reverse_enum = reverse_enum

    def default_value(self) -> str | int:
        return self.reverse_enum.get(0, 0)

    def serialize_value(self, value: str | int) -> list[bytes]:
        return [bytes([self.enum[value] if isinstance(value, str) else value])]

    def deserialize_value(self, frames: list[BufferType]) -> str | int:
        if len(frames) != 1:
            raise ValueError(f"Expected one frame but got {len(frames)}")
        frame = frames[0]
        if len(frame) != 1:
            raise ValueError(f"Expected one byte but got {len(frame)}")
        return self.reverse_enum.get(frame[0], frame[0])


class _ScalarStructValue(_ValueObject):
    """A scalar value consisting of an instance of a struct as defined in the schema."""

    __slots__ = ["msg", "struct_name"]

    def __init__(self, msg: RuntimeZiplineMessage, struct_name: str) -> None:
        """Initializes the object to manipulate the value."""
        self.msg = msg
        self.struct_name = struct_name

    def default_value(self) -> Mapping[str, Any]:
        return self.msg.create(self.struct_name)

    def serialize_value(self, value: Mapping[str, Any]) -> list[bytes]:
        return [self.msg.serialize(self.struct_name, value)]

    def deserialize_value(self, frames: list[BufferType]) -> _StructMapping:
        if len(frames) != 1:
            raise ValueError(f"Expected one frame but got {len(frames)}")
        return self.msg.deserialize(self.struct_name, frames[0])


class _ArrayBytesValue(_ValueObject):
    """A fixed size array value consisting of bytes."""

    __slots__ = ["size"]

    def __init__(self, size: int) -> None:
        """Initializes the object to manipulate the value."""
        self.size = size

    def default_value(self) -> bytearray:
        return bytearray(self.size)

    def serialize_value(self, values: BufferType | Sequence[int]) -> list[bytes]:
        if len(values) != self.size:
            raise ValueError(f"Array size {len(values)} != {self.size}")
        return [bytes(values)]

    def deserialize_value(self, frames: list[BufferType]) -> bytearray:
        values = bytearray()
        for f in frames:
            values.extend(f)
        if len(values) != self.size:
            raise ValueError(f"Expected {self.size} bytes but got {len(values)}")
        return values


class _ArrayBuiltinValue(_ValueObject):
    """A fixed size array value consisting of built-in types such as integers, float, bools, etc."""

    __slots__ = ["packer", "size"]

    def __init__(self, size: int, packer: struct.Struct) -> None:
        """Initializes the object to manipulate the value."""
        self.size = size
        self.packer = packer

    def default_value(self) -> list:
        return [self.packer.unpack(b"\0" * self.packer.size)[0]] * self.size

    def serialize_value(self, values: Sequence) -> list[bytes]:
        if len(values) != self.size:
            raise ValueError(f"Array size {len(values)} != {self.size}")
        return [b"".join(self.packer.pack(v) for v in values)]

    def deserialize_value(self, frames: list[BufferType]) -> list:
        values: list = []
        for f in frames:
            values.extend(x[0] for x in self.packer.iter_unpack(f))
        if len(values) != self.size:
            raise ValueError(f"Expected {self.size} values but got {len(values)}")
        return values


class _ArrayEnumValue(_ValueObject):
    """A fixed size array value consisting of enums as defined in the schema.

    Enum values are nominally a string name.
      If the name isn't known, though, the value will be its integer instead.
    """

    __slots__ = ["enum", "reverse_enum", "size"]

    def __init__(self, size: int, enum: Mapping[str, int], reverse_enum: Mapping[int, str]) -> None:
        """Initializes the object to manipulate the value."""
        self.size = size
        self.enum = enum
        self.reverse_enum = reverse_enum

    def default_value(self) -> list[str | int]:
        return [self.reverse_enum.get(0, 0)] * self.size

    def serialize_value(self, values: Sequence[str | int]) -> list[bytes]:
        if len(values) != self.size:
            raise ValueError(f"Array size {len(values)} != {self.size}")
        return [bytes(self.enum[v] if isinstance(v, str) else v for v in values)]

    def deserialize_value(self, frames: list[BufferType]) -> list[str | int]:
        values = bytearray()
        for f in frames:
            values.extend(f)
        if len(values) != self.size:
            raise ValueError(f"Expected {self.size} enums but got {len(values)}")
        return [self.reverse_enum.get(v, v) for v in values]


class _ArrayStructValue(_ValueObject):
    """A fixed size array value consisting of instances of a struct as defined in the schema."""

    __slots__ = ["msg", "size", "struct_name"]

    def __init__(self, size: int, msg: RuntimeZiplineMessage, struct_name: str) -> None:
        """Initializes the object to manipulate the value."""
        self.size = size
        self.msg = msg
        self.struct_name = struct_name

    def default_value(self) -> list[Mapping[str, Any]]:
        return [self.msg.create(self.struct_name) for _ in range(self.size)]

    def serialize_value(self, values: Sequence[Mapping[str, Any]]) -> list[bytes]:
        if len(values) != self.size:
            raise ValueError(f"Array size {len(values)} != {self.size}")
        return [self.msg.serialize(self.struct_name, v) for v in values]

    def deserialize_value(self, frames: list[BufferType]) -> list[Mapping[str, Any]]:
        return [self.msg.deserialize(self.struct_name, f) for f in frames if f]


class _VectorBytesValue(_ValueObject):
    """A variable size array value consisting of bytes."""

    __slots__ = ["size"]

    def __init__(self, size: int) -> None:
        """Initializes the object to manipulate the value."""
        self.size = size

    def default_value(self) -> bytearray:
        return bytearray()

    def serialize_value(self, values: BufferType | Sequence[int]) -> list[bytes]:
        if len(values) > self.size:
            raise ValueError(f"Vector size {len(values)} > {self.size}")
        return [bytes(values)] if values else []

    def deserialize_value(self, frames: list[BufferType]) -> bytearray:
        values = bytearray()
        for f in frames:
            values.extend(f)
        if len(values) > self.size:
            raise ValueError(f"Expected no more than {self.size} bytes but got {len(values)}")
        return values


class _VectorBuiltinValue(_ValueObject):
    """A variable size array value consisting of built-in types such as integers, float, bools, etc."""

    __slots__ = ["packer", "size"]

    def __init__(self, size: int, packer: struct.Struct) -> None:
        """Initializes the object to manipulate the value."""
        self.size = size
        self.packer = packer

    def default_value(self) -> list:
        return []

    def serialize_value(self, values: list) -> list[bytes]:
        if len(values) > self.size:
            raise ValueError(f"Vector size {len(values)} > {self.size}")
        return [b"".join(self.packer.pack(v) for v in values)] if values else []

    def deserialize_value(self, frames: list[BufferType]) -> list:
        values: list = []
        for f in frames:
            values.extend(x[0] for x in self.packer.iter_unpack(f))
        if len(values) > self.size:
            raise ValueError(f"Expected no more than {self.size} values but got {len(values)}")
        return values


class _VectorEnumValue(_ValueObject):
    """A variable size array value consisting of enums as defined in the schema.

    Enum values are nominally a string name.
      If the name isn't known, though, the value will be its integer instead.
    """

    __slots__ = ["enum", "reverse_enum", "size"]

    def __init__(self, size: int, enum: Mapping[str, int], reverse_enum: Mapping[int, str]) -> None:
        """Initializes the object to manipulate the value."""
        self.size = size
        self.enum = enum
        self.reverse_enum = reverse_enum

    def default_value(self) -> list[str | int]:
        return []

    def serialize_value(self, values: Sequence[str | int]) -> list[bytes]:
        if len(values) > self.size:
            raise ValueError(f"Vector size {len(values)} > {self.size}")
        return [bytes(self.enum[v] if isinstance(v, str) else v for v in values)] if values else []

    def deserialize_value(self, frames: list[BufferType]) -> list[str | int]:
        values = bytearray()
        for f in frames:
            values.extend(f)
        if len(values) > self.size:
            raise ValueError(f"Expected no more than {self.size} enums but got {len(values)}")
        return [self.reverse_enum.get(v, v) for v in values]


class _VectorStructValue(_ValueObject):
    """A variable size array value consisting of instances of a struct as defined in the schema."""

    __slots__ = ["msg", "size", "struct_name"]

    def __init__(self, size: int, msg: RuntimeZiplineMessage, struct_name: str) -> None:
        """Initializes the object to manipulate the value."""
        self.size = size
        self.msg = msg
        self.struct_name = struct_name

    def default_value(self) -> list[Mapping[str, Any]]:
        return []

    def serialize_value(self, values: Sequence[Mapping[str, Any]]) -> list[bytes]:
        if len(values) > self.size:
            raise ValueError(f"Vector size {len(values)} > {self.size}")
        return [self.msg.serialize(self.struct_name, v) for v in values]

    def deserialize_value(self, frames: list[BufferType]) -> list[Mapping[str, Any]]:
        return [self.msg.deserialize(self.struct_name, f) for f in frames if f]


class _BitfieldValue(_ValueObject):
    """A bitfield containing one or more named bits.

    Bitfields are internally represented as bytes.
    While similar to a vector of bytes, bitfields have a fixed size
    in-memory but a variable size when serialized.
    """

    __slots__ = ["bits", "num_bytes"]

    def __init__(self, bits: Mapping[str, int], num_bytes: int) -> None:
        """Initializes the object to manipulate the value."""
        self.bits = bits
        self.num_bytes = num_bytes

    def default_value(self) -> _StructMapping:
        return _StructMapping(dict.fromkeys(self.bits, False))

    def serialize_value(self, values: Mapping[str, bool]) -> list[bytes]:
        if values.keys() != self.bits.keys():
            raise ValueError(f"Bitfield bits {values.keys()} != {self.bits.keys()}")
        fields = bytearray(self.num_bytes)
        for name, i in self.bits.items():
            if values[name]:
                byte = i // 8
                bit = i % 8
                fields[byte] |= 1 << bit
        try:
            while not fields[-1]:
                fields.pop()
            return [fields]  # noqa: TRY300
        except IndexError:
            return []

    def deserialize_value(self, frames: list[BufferType]) -> _StructMapping:
        fields = bytearray()
        for f in frames:
            fields.extend(f)
        values = self.default_value()
        for name, i in self.bits.items():
            byte = i // 8
            bit = i % 8
            try:
                if fields[byte] & (1 << bit):
                    values[name] = True
            except IndexError:
                break
        return values


class _UnionField:
    """A field object that implements the semantics of a union.

    Union fields are mutually exclusive with other fields in the same union.
    """

    __slots__ = ["_field_name", "_union_name", "_value"]

    def __init__(self, union_name: str, field_name: str, value: _ValueObject) -> None:
        """Initializes the object to modify the field under the specified union.

        Arguments:
            union_name: The name of the union the field belongs to.
            field_name: The name of the field.
            value: The value object to use to manipulate the value in the field.
        """
        self._union_name = union_name
        self._field_name = field_name
        self._value = value

    def set_default(self, instance: dict[str, Any]) -> None:
        """Modifies the specified struct instance to contain the field as an option within the union."""
        if self._union_name not in instance:
            instance[self._union_name] = _UnionMapping()
        instance[self._union_name].add_field(self._field_name, self._value.default_value)

    def serialize(self, instance: Mapping[str, Any]) -> list[bytes]:
        """Serializes the field, returning a list of zero or more frames."""
        try:
            union = instance[self._union_name]
        except KeyError as e:
            raise ValueError(f"Union field {self._union_name} is missing") from e
        try:
            value = union[self._field_name]
        except KeyError:
            return []  # Not set to this field
        try:
            # If there isn't any data at all, then we need to write a null frame. This ensures that the union's
            # validity is communicated in the absence of any data to write. This will only happen for empty vectors
            # or bitfields without any set bits.
            return self._value.serialize_value(value) or [b""]
        except Exception as e:
            raise ValueError from e

    def deserialize(self, instance: dict[str, Any], frames: list[BufferType]) -> None:
        """Deserializes the field from a list of frames, writing it into the specified struct instance."""
        if self._union_name not in instance:
            instance[self._union_name] = _UnionMapping()
        union = instance[self._union_name]
        union.add_field(self._field_name, self._value.default_value)
        # If there's no data, the union wasn't set to this value.
        if frames:
            if union and self._field_name not in union:
                raise ValueError(f"Multiple fields for union {self._union_name}")
            union[self._field_name] = self._value.deserialize_value(frames)


class _PackedField:
    """A field object that implements the semantics of a packed scalar or array type.

    Packed fields must always have a value within it.
    """

    __slots__ = ["_field_name", "_value"]

    def __init__(self, field_name: str, value: _ValueObject) -> None:
        """Initializes the object to modify the field.

        Arguments:
            field_name: The name of the field.
            value: The value object to use to manipulate the value in the field.
        """
        self._field_name = field_name
        self._value = value

    def set_default(self, instance: dict[str, Any]) -> None:
        """Modifies the specified struct instance to contain the field, with a default value."""
        instance[self._field_name] = self._value.default_value()

    def serialize(self, instance: Mapping[str, Any]) -> list[bytes]:
        """Serializes the field, returning a list at least one frame."""
        try:
            value = instance[self._field_name]
            return self._value.serialize_value(value)
        except Exception as e:
            raise ValueError from e

    def deserialize(self, instance: dict[str, Any], frames: list[BufferType]) -> None:
        """Deserializes the field from a list of frames, writing it into the specified struct instance."""
        try:
            instance[self._field_name] = self._value.deserialize_value(frames)
        except Exception as e:
            raise ValueError from e


class _OptionalField:
    """A field object that implements the semantics of an optional (not packed) scalar or array type.

    Optional fields aren't required to have a value in it.
    """

    __slots__ = ["_field_name", "_value"]

    def __init__(self, field_name: str, value: _ValueObject) -> None:
        """Initializes the object to modify the field.

        Arguments:
            field_name: The name of the field.
            value: The value object to use to manipulate the value in the field.
        """
        self._field_name = field_name
        self._value = value

    def set_default(self, instance: dict[str, Any]) -> None:
        """Modifies the specified struct instance to contain the field, without a value."""
        instance[self._field_name] = None

    def serialize(self, instance: Mapping[str, Any]) -> list[bytes]:
        """Serializes the field, returning a list of zero or more frames."""
        try:
            value = instance[self._field_name]
            if value is None:
                return []
            return self._value.serialize_value(value)
        except Exception as e:
            raise ValueError from e

    def deserialize(self, instance: dict[str, Any], frames: list[BufferType]) -> None:
        """Deserializes the field from a list of frames, writing it into the specified struct instance."""
        try:
            instance[self._field_name] = self._value.deserialize_value(frames) if frames else None
        except Exception as e:
            raise ValueError from e


class _VectorField:
    """A field object that implements the semantics of a vector or bitfield.

    Outside of a union, vectors and bitfields always implicitly exist.
    """

    __slots__ = ["_field_name", "_value"]

    def __init__(self, field_name: str, value: _ValueObject) -> None:
        """Initializes the object to modify the field.

        Arguments:
            field_name: The name of the field.
            value: The value object to use to manipulate the value in the field.
        """
        self._field_name = field_name
        self._value = value

    def set_default(self, instance: dict[str, Any]) -> None:
        """Modifies the specified struct instance to contain the field, with its default value."""
        instance[self._field_name] = self._value.default_value()

    def serialize(self, instance: Mapping[str, Any]) -> list[bytes]:
        """Serializes the field, returning a list of zero or more frames."""
        try:
            value = instance[self._field_name]
            return self._value.serialize_value(value)
        except Exception as e:
            raise ValueError from e

    def deserialize(self, instance: dict[str, Any], frames: list[BufferType]) -> None:
        """Deserializes the field from a list of frames, writing it into the specified struct instance.

        Args:
            instance (dict[str, Any]): The struct instance to deserialize into.
            frames (list[BufferType]): The list of frames to deserialize from.

        Raises:
            ValueError: The field is invalid.
            Exception: An unexpected error occurred.
        """
        try:
            instance[self._field_name] = self._value.deserialize_value(frames)
        except Exception as e:
            raise ValueError from e


def from_annotations(annotations: str, version: int = MAX_SCHEMA_VERSION) -> RuntimeZiplineMessage:
    """Dynamically create a message parser.

    The annotation must not contain any imports.

    Args:
        annotations: A string containing a flat message definition without any imports.
        version: The version of the schema. This is a semantic version number
                that must be incremented any time the schema semantics change.

    Returns: A RuntimeZiplineMessage instance able to create, serialze and deserialize structs.

    Raises:
        ValueError: The annotations are invalid
        UnsupportedSchemaVersion: The version of the schema is not supported.
    """
    if version > MAX_SCHEMA_VERSION:
        raise UnsupportedSchemaVersion(
            f"Version {version} not supported. Max supported is {MAX_SCHEMA_VERSION}"
        )
    return RuntimeZiplineMessage(parse(io.StringIO(annotations)))


def from_zmd(
    zmd: str, import_root: str, version: int = MAX_SCHEMA_VERSION
) -> RuntimeZiplineMessage:
    """Dynamically create a message parser.

    Dynamically creates a message parser for the given zmd file. flattening any imports as needed.
    This is useful when creating zipline messages within python.

    Args:
        zmd: A string containing the path of a zmd file to load.
        import_root: The path to read imported zmd files relative to.
        version: The version of the schema. This is a semantic version number that must be
            incremented any time the schema semantics change.

    Returns: A RuntimeZiplineMessage instance able to create, serialze and deserialize structs.

    Raises:
        ValueError: The annotations are invalid
        UnsupportedSchemaVersion: The version of the schema is not supported.
    """
    if version > MAX_SCHEMA_VERSION:
        raise UnsupportedSchemaVersion(
            f"Version {version} not supported. Max supported is {MAX_SCHEMA_VERSION}"
        )
    with Path(zmd).open() as f:
        return RuntimeZiplineMessage(flatten(parse(f), import_root))


def from_zmds(
    relative_zmd_paths: Iterable[str],
    import_root: str,
    version: int = MAX_SCHEMA_VERSION,
) -> RuntimeZiplineMessage:
    """Dynamically create a message parser.

    Dynamically creates a message parser for the given zmd files. flattening any imports as needed.
    This is useful when creating zipline messages within python.

    Args:
        relative_zmd_paths: The list of relative paths to the zmd files to load.
        import_root: The path to read imported zmd files relative to.
        version: The version of the schema. This is a semantic version number
            that must be incremented any time the schema semantics change.

    Returns: A RuntimeZiplineMessage instance able to create, serialze and deserialize structs.

    Raises:
        ValueError: The annotations are invalid
        UnsupportedSchemaVersion: The version of the schema is not supported.
    """
    if version > MAX_SCHEMA_VERSION:
        raise UnsupportedSchemaVersion(
            f"Version {version} not supported. Max supported is {MAX_SCHEMA_VERSION}"
        )

    file_zmd_map: dict[str, ParsedZmd] = {}
    for path in relative_zmd_paths:
        with (Path(import_root) / path).open() as f:
            file_zmd_map[path] = parse(f)
    merged_zmd = merge_named_zmds(file_zmd_map, import_root)
    return RuntimeZiplineMessage(flatten(merged_zmd, import_root))
