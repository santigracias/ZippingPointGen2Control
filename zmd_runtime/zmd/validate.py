"""Functions for validating raw and parsed ZMD documents."""

import itertools
from typing import Any, Mapping

import jsonschema
from jsonschema.exceptions import ValidationError

from .errors import ZmdParseError, ZmdReferenceError, ZmdSyntaxError
from .parsed_zmd_schema import PARSED_DOCUMENT_SCHEMA
from .raw_zmd_schema import (
    ENUM_STATEMENT,
    FROM_STATEMENT,
    PRIMITIVE_TYPES,
    SIZE_STATEMENT,
    STRUCT_STATEMENT,
)
from .util import ZmdNode


def validate_raw_zmd_schema(document: Mapping[str, Any]):
    """Ensure that the input ZMD document adheres to the ZMD syntax rules.

    Args:
        document: The raw ZMD document, after being loaded by a YAML parser.

    Raises:
        ZmdSyntaxError if the document contains any invalid syntax.
    """
    # We first need to turn the document into an intermediate format that has categorized the statements based
    # on keyword. This avoids creating an unnecessarily complicated schema for the base document.
    schema: Mapping[str, Any] = {
        "type": "object",
        "properties": {
            "from": FROM_STATEMENT,
            "enum": ENUM_STATEMENT,
            "size": SIZE_STATEMENT,
            "struct": STRUCT_STATEMENT,
        },
        "additionalProperties": False,
    }
    statements: Mapping[str, Any] = {key: {} for key in schema["properties"]}
    for statement, body in document.items():
        keyword = statement.split()[0]
        if keyword not in statements.keys():
            raise ZmdSyntaxError(f"Statement does not start with a recognized keyword: {statement}")
        statements[keyword][statement] = body

    try:
        jsonschema.validate(statements, schema)
    except ValidationError as e:
        raise ZmdSyntaxError from e


def validate_parsed_zmd_schema(parsed: Mapping):
    """Ensures that the parsed ZMD output adheres to the schema defined in `parsed_zmd_schema`.

    Raises ZmdParseError if the output format is incorrect.
    """
    try:
        jsonschema.validate(parsed, PARSED_DOCUMENT_SCHEMA)
    except ValidationError as e:
        raise ZmdParseError from e


def _check_for_collisions(names):
    "Ensures that all of the names in the iterator are unique, and returns a set of the validated names."
    claimed_names = set()
    for name in names:
        if name in claimed_names:
            raise ZmdReferenceError(f"Multiple conflicting definitions for {name}")
        claimed_names.add(name)
    return claimed_names


def validate_references(parsed: Mapping):
    """Validates all type, instance and field names in the parsed document for local consistency.

    Checks for name collisions, duplicate names, undefined names, and unused imports.

    Does NOT attempt to actually resolve imported symbols.

    Raises:
        ZmdParseError or ZmdReferenceError if the document is invalid.
    """

    # Compile the various imported types.
    imported_structs = []
    imported_enums = []
    imported_sizes = []
    for imported in parsed["imports"].values():
        imported_structs.extend(imported["structs"])
        imported_enums.extend(imported["enums"])
        imported_sizes.extend(imported["sizes"])

    # Enum and struct names should not conflict with each other, nor with the core types.
    types_in_scope = itertools.chain(
        # Current symbol names, including superficial renames.
        parsed["structs"].keys(),
        parsed["enums"].keys(),
        # Original symbol names for renames (used for wire format and must be unique).
        [v["was"] for v in parsed["structs"].values() if "was" in v],
        [v["was"] for v in parsed["enums"].values() if "was" in v],
        # Imported symbols.
        imported_structs,
        imported_enums,
        PRIMITIVE_TYPES,
    )
    known_types = _check_for_collisions(types_in_scope)

    # Imported symbols will be removed from this set as we identify structs that use them.
    # Anything leftover will be flagged as an unused import.
    unused_imported_types = set(imported_structs + imported_enums)
    unused_imported_sizes = set(imported_sizes)

    # Sizes are simpler, since they can't be renamed. We don't have to compare them against the type names since these
    # represent "instances" rather than "types".
    sizes = itertools.chain(parsed["sizes"].keys(), imported_sizes)
    known_sizes = _check_for_collisions(sizes)

    # Validate the field names, types, and symbolic array bounds within each struct.
    for struct_key, struct in parsed["structs"].items():
        struct = ZmdNode(struct)  # We need some extra functionality on top of the dict.

        # The struct name should match its key.
        if struct_key != struct["name"]:
            raise ZmdParseError(
                f"Struct name does not match struct key ({struct_key} != {struct['name']})"
            )

        # Field names should be unique, accounting for renames.
        # TODO: Should bit names be allowed to overlap because their names are scoped to their bitfield?
        field_names = [field["name"] for field in struct.flat_fields() if "name" in field]
        # TODO: Why do old names matter? Just to avoid confusing analysis scripts?
        old_field_names = [field["was"] for field in struct.flat_fields() if "was" in field]
        _check_for_collisions(field_names + old_field_names)

        # Bits within a bitfield should not conflict.
        for field in struct.flat_fields():
            if "bitfield" in field:
                bit_names = [bit["name"] for bit in field.bits() if "name" in bit]
                old_bit_names = [bit["was"] for bit in field.bits() if "was" in bit]
                _check_for_collisions(bit_names + old_bit_names)

        # All fields should refer to type that is in scope.
        for field_type in struct.referenced_types():
            if field_type not in known_types:
                raise ZmdReferenceError(f"Unrecognized type {field_type} in {struct['name']}")
            unused_imported_types.discard(field_type)

        # All array-like fields should either use a literal size or a named size that's in scope.
        for size in struct.referenced_sizes():
            if size not in known_sizes:
                raise ZmdReferenceError(f"Unrecognized array bound {size} in {struct['name']}")
            unused_imported_sizes.discard(size)

        # TODO: Check for hash collisions? This is tough without reading all imports

    # The items within an enum should not conflict. Note that we don't actually care about renames.
    for enum in parsed["enums"].values():
        _check_for_collisions(enum["values"].keys())

    if unused_imported_sizes:
        raise ZmdReferenceError(f"Sizes are imported but unused: {unused_imported_sizes}")
    if unused_imported_types:
        raise ZmdReferenceError(f"Custom types are imported but unused: {unused_imported_types}")
