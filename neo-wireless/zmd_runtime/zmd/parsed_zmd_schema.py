"""Validation rules that apply to the output of the ZMD parser.

Rules are defined according to the JSON Schema specification.

See test/zmd_parser_test.py for an example input ZMD and corresponding parsed output.
"""

from .raw_zmd_schema import NAME, mutual_exclusion

PARSED_NAME = {"type": "string", "pattern": NAME}

# Parsed bitfields are a list of parsed bit names. Bits can either be named or unnamed.
# Example: [ { "name": "BIT_1"}, { "was": "BIT_2" }, { "name": "BIT_3" } ]
PARSED_BITFIELD = {
    "type": "array",
    "items": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "name": {"type": "string"},
            "was": {"type": "string"},
        },
        "dependentSchemas": mutual_exclusion("name", "was"),
    },
}

# Parsed unions are a list of dicts with "name", "was" and "type" keys.
PARSED_UNION = {
    "type": "array",
    "items": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "name": PARSED_NAME,
            "was": PARSED_NAME,
            "union_name": PARSED_NAME,
            "type": {"type": "string"},  # This "type" is an actual key, not a rule
            "bitfield": PARSED_BITFIELD,
        },
        "dependentSchemas": mutual_exclusion("type", "bitfield"),
    },
}

# Parsed structs are dicts with a "name", "was", and "fields" key.
# Parsed struct fields are a list of dicts with "name", "was", and either a "type", "union", or "bitfield" key.
PARSED_STRUCT = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "name": PARSED_NAME,
        "was": PARSED_NAME,
        "fields": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "name": PARSED_NAME,
                    "was": PARSED_NAME,
                    "type": {"type": "string"},
                    "union": PARSED_UNION,
                    "bitfield": PARSED_BITFIELD,
                },
                "dependentSchemas": mutual_exclusion("type", "union", "bitfield"),
            },
        },
    },
}

# Parsed enums are dicts with a "name", "was", and "values" key. The "values" value is a dict that maps enum names to
# their corresponding values. Note that these names DO NOT include "unnamed" enum values.
PARSED_ENUM = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "name": PARSED_NAME,
        "was": PARSED_NAME,
        "values": {
            "type": "object",
            "propertyNames": PARSED_NAME,
            "additionalProperties": {"type": "integer", "minimum": 0, "maximum": 255},
        },
    },
}

# A parsed ZMD document contains a top-level "struct", "enum", "size", and "imports" key.
#
# The "struct"/"enum"/"size" value is a mapping of struct/enum/size names to parsed structs/enums/sizes.
# The names are always the current name, not the name specified by a "was" statement.
#
# The "import" value is a mapping of import paths to the symbols that they import.
PARSED_DOCUMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "structs": {
            "type": "object",
            "propertyNames": PARSED_NAME,
            "additionalProperties": PARSED_STRUCT,
        },
        "enums": {
            "type": "object",
            "propertyNames": PARSED_NAME,
            "additionalProperties": PARSED_ENUM,
        },
        "sizes": {
            "type": "object",
            "propertyNames": PARSED_NAME,
            "additionalProperties": {"type": "integer", "minimum": 0},
        },
        "imports": {
            "type": "object",
            "additionalProperties": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "enums": {"type": "array", "items": PARSED_NAME},
                    "structs": {"type": "array", "items": PARSED_NAME},
                    "sizes": {"type": "array", "items": PARSED_NAME},
                },
                "required": ["enums", "structs", "sizes"],
            },
        },
    },
    "additionalProperties": False,
}
