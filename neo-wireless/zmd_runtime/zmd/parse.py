"""Provides a `parse` function which parses ZMD documents into a structured output format.

See parsed_zmd_schema for details on the output format.
"""

import re
from typing import Mapping, TextIO, cast

import yaml

from .errors import ZmdParseError, ZmdSyntaxError
from .parsed_zmd_schema import PARSED_DOCUMENT_SCHEMA
from .parser_types import (
    ParsedZmd,
    ParsedZmdEnum,
    ParsedZmdImports,
    ParsedZmdName,
    ParsedZmdStruct,
    ParsedZmdStructField,
)
from .raw_zmd_schema import NAME, PRIMITIVE_TYPES
from .util import ZmdNode
from .validate import (
    validate_parsed_zmd_schema,
    validate_raw_zmd_schema,
    validate_references,
)


def _parse_name(expression: str) -> ParsedZmdName:
    """Parses an expression that may contain a potentially renamed identifier.

    Args:
        expression: The text to parse.

    Returns:
        A dict with optional "name" and "was" keys, containing the parsed identifiers.

    Example inputs:
        struct MyStruct (was YourStruct)
        struct MyStruct
        enum MyEnum (was YourEnum)
        enum MyEnum
        size MySize (was YourSize)
        size MySize
        my_field (was your_field)
        my_field
        (was your_bit)
    """

    NAME_PAT = re.compile(
        rf"""
        ^((struct|enum|size)[ ])?           # Optional type keyword.
        (?P<name>{NAME})?\ ?                # Optional name.
        (\(was\ (?P<old_name>{NAME})\))?$   # Optional 'was' statement with the original name.
    """,
        re.VERBOSE,
    )

    name_pat = NAME_PAT.match(expression)
    if name_pat is None:
        raise ZmdParseError(f"Invalid name expression: {expression}")

    parsed: ParsedZmdName = {}
    if name_pat.group("name") is not None:
        parsed["name"] = name_pat.group("name")
    if name_pat.group("old_name") is not None:
        parsed["was"] = name_pat.group("old_name")

    return parsed


def _parse_struct_field(field: Mapping) -> ParsedZmdStructField:
    """Parses a ZMD struct field into the output format.

    Args:
        field: The single-item mapping containing the field declaration and contents.

    Returns:
        A mapping with the following structure:

        {
            "name": parsed_name,      # If present in declaration
            "was": parsed_was_name,   # If present in declaration
            "type": field_type_str,   # If the field is not a union or bitfield
            "union": [ union_fields... ],  # If the field is a union. Each subfield is structured like a top-level
                                           # field, minus union options.
            "bitfield": [ bit_names... ],  # If the field is a bitfield. Each bit is just a parsed name.
        }
    """
    declaration, definition = next(iter(field.items()))

    name = _parse_name(declaration)
    result = cast(ParsedZmdStructField, name)
    if isinstance(definition, str):
        # Normal field.
        result["type"] = definition
    elif isinstance(definition, list):
        if isinstance(definition[0], dict):
            # Union.
            subfields = [_parse_struct_field(subfield) for subfield in definition]
            for subfield in subfields:
                subfield["union_name"] = name["name"]
            result["union"] = subfields
        else:
            # Bitfield
            bits = [_parse_name(bit) for bit in definition]
            result["bitfield"] = bits

    return result


def _parse_import_path(statement: str) -> str:
    "Extract the import path from a 'from' statement."
    return statement.replace("from", "").replace('"', "").strip()


def parse(text: TextIO) -> ParsedZmd:
    """Validated and parse a ZMD document into a structured output format.

    Args:
        text: open file containing the ZMD contents.

    Returns:
        A dict. See `parsed_zmd_schema` for a full description of the output structure.

    Raises:
        ZmdSyntaxError if the input contains invalid syntax.
        ZmdReferenceError if the input contains name collisions or undefined symbols.
        ZmdParseError if the input or output is invalid for any other reason.
    """
    try:
        # Attempt to read the file as a YAML document.
        try:
            document = yaml.safe_load(text)
            if document is None:
                # If the input text is empty, yaml.safe_load returns None instead of an empty dict.
                # However, in our case, it's probably more graceful to just treat an empty file the same as an empty dict.
                document = {}
        except yaml.YAMLError as e:
            raise ZmdSyntaxError(e)

        # Validate the ZMD syntax. Raises an exception if the syntax is invalid.
        validate_raw_zmd_schema(document)

        # Rework the raw ZMD structure into a more automation-friendly format.
        # See parsed_zmd_schema.py for reference.
        parsed: ParsedZmd = {
            "enums": {},
            "sizes": {},
            "structs": {},
            "imports": {},
        }
        for statement, body in document.items():
            if statement.startswith("enum"):
                values = {}
                for enum_name, enum_value in body.items():
                    name = _parse_name(enum_name).get("name")
                    if name is None:
                        continue  # Skip unnamed enums
                    values[name] = int(enum_value)

                enum = cast(ParsedZmdEnum, _parse_name(statement))
                enum["values"] = values
                parsed["enums"][enum["name"]] = enum

            elif statement.startswith("size"):
                name = _parse_name(statement).get("name")  # Sizes can't be renamed.
                if name is None:
                    raise ZmdSyntaxError
                parsed["sizes"][name] = int(body)

            elif statement.startswith("struct"):
                fields = [_parse_struct_field(field) for field in body]
                struct = cast(ParsedZmdStruct, _parse_name(statement))
                struct["fields"] = fields
                parsed["structs"][struct["name"]] = struct

            elif statement.startswith("from"):
                path = _parse_import_path(statement)
                imports: ParsedZmdImports = {"enums": [], "sizes": [], "structs": []}
                for symbol in body:
                    keyword, name = symbol.split()
                    if name is None:
                        raise ZmdSyntaxError

                    # This is verbose but necessary because TypedDicts require keys to be literals.
                    if keyword == "enum":
                        imports["enums"].append(name)
                    elif keyword == "size":
                        imports["sizes"].append(name)
                    elif keyword == "struct":
                        imports["structs"].append(name)
                    else:
                        raise ZmdSyntaxError(f"Unrecognized keyword in 'from' statement: {keyword}")

                parsed["imports"][path] = imports

        # Explicitly validate the output to make sure it adheres to the advertised schema.
        # Raises an exception if the parsed output is invalid.
        validate_parsed_zmd_schema(parsed)

        # Check all of the symbol names. Raises an exception if duplicate/undefined symbols are present in this document.
        # Does _not_ attempt to resolve references in other ZMD files; only checks for local consistency.
        validate_references(parsed)
    except Exception as e:
        try:
            e.add_note(f"While parsing {text}")
        except AttributeError:
            pass
        raise e
    return parsed
