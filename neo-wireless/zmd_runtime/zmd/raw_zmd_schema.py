"""Syntax and grammar rules for validating input ZMD files.

Rules are defined according to the JSON Schema specification.
"""

from typing import Any, Dict, Union

###############################################################################
# Regular expressions for validating specific syntax elements.
###############################################################################

NAME = r"([a-zA-Z_][a-zA-Z0-9_]*)"
POSITIVE_INTEGER = r"([1-9][0-9]*)"
SCALAR_TYPE = NAME

# Matches MyType[10] or MyType[MY_SIZE].
ARRAY_TYPE = rf"({NAME}\[({NAME}|{POSITIVE_INTEGER})\])"

# Matches MyType[<=10] or MyType[<=MY_SIZE].
VECTOR_TYPE = rf"({NAME}\[<=({NAME}|{POSITIVE_INTEGER})\])"

# Matches:
# - MyType
# - MyType[10]
# - MyType[MY_SIZE]
# - MyType[<=MY_SIZE]
ANY_TYPE_WITHOUT_PACKED = rf"({SCALAR_TYPE}|{ARRAY_TYPE}|{VECTOR_TYPE})"

# Additionally matches:
# - packed MyType
# - packed MyType[10]
# - packed MyType[MY_SIZE]
# - packed MyType[<=MY_SIZE]
ANY_TYPE = rf"((packed\ )?{ANY_TYPE_WITHOUT_PACKED})"

# Matches my_name OR (was your_name) BUT NOT my_name (was your_name).
UNNAMEABLE_NAME = rf"({NAME}|\(was {NAME}\))"

# Matches my_name OR (was your_name) OR my_name (was your_name).
VERSIONED_NAME = rf"({NAME}|\(was\ {NAME}\)|{NAME}\ \(was\ {NAME}\))"

# Set of types that are provided by the ZMD language.
PRIMITIVE_TYPES = set(["bool", "f32", "f64", "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64"])

###############################################################################


SchemaRules = Union[int, str, Dict[str, Any]]


def expression(regex: str) -> Dict[str, str]:
    """Schema rules for a string that must match a regex."""
    return {"type": "string", "pattern": f"^{regex}$"}


def mutual_exclusion(*properties: str) -> SchemaRules:
    """Schema rules for a set of mutually exclusive properties.

    Should be the value of "dependentSchemas".
    """
    props = set(properties)
    return {p: {"not": {"anyOf": [{"required": [other]} for other in props - {p}]}} for p in props}


def single_entry_dict(key: SchemaRules, value: SchemaRules) -> Dict[str, SchemaRules]:
    """Schema rules for a dict that should contain exactly 1 element."""
    return {
        "type": "object",
        "propertyNames": key,
        "additionalProperties": value,
        "minProperties": 1,
        "maxProperties": 1,
    }


def statement(expr: SchemaRules, value: SchemaRules) -> Dict[str, SchemaRules]:
    """Schema rules for a top-level statement (import/symbol declaration)."""
    return {
        "type": "object",
        "propertyNames": expr,
        "additionalProperties": value,
    }


# Size definitions are positive integers.
# Sizes aren't encoded on the wire, so their names don't need to be versioned.
SIZE_STATEMENT = statement(expr=expression(f"size {NAME}"), value={"type": "integer", "minimum": 0})

# Enum definitions are mappings of names to values between 0 and 255.
# Enum names are used in the wire encoding, so they must be versioned.
ENUM_STATEMENT = statement(
    expr=expression(f"enum {VERSIONED_NAME}"),
    value={
        "type": "object",
        "propertyNames": expression(UNNAMEABLE_NAME),
        "additionalProperties": {"type": "integer", "minimum": 0, "maximum": 255},
    },
)

STRUCT_FIELD = single_entry_dict(
    # Field name. Note that this is the most general format, but unions aren't allowed to include
    # a 'was' expression.
    key=expression(VERSIONED_NAME),
    # Field contents: can either be a string representing the type, a list of name/type pairs, or a list of bit names.
    value={
        "oneOf": [
            # 'Normal' field.
            expression(ANY_TYPE),
            # Union or bitfield.
            {
                "type": "array",
                "items": {
                    "oneOf": [
                        # Union are lists of name: type mappings.
                        single_entry_dict(
                            key=expression(VERSIONED_NAME),
                            # Unions can have bitfields in them.
                            value={
                                "oneOf": [
                                    expression(ANY_TYPE_WITHOUT_PACKED),
                                    {
                                        "type": "array",
                                        "items": expression(UNNAMEABLE_NAME),
                                    },
                                ],
                            },
                        ),
                        # Bitfields are lists of names.
                        expression(UNNAMEABLE_NAME),
                    ],
                },
            },
        ]
    },
)

# Struct definitions are lists of fields.
STRUCT_STATEMENT = statement(
    expr=expression(f"struct {VERSIONED_NAME}"),
    value={"type": "array", "items": STRUCT_FIELD},
)

# 'from' statements are a list of imported types.
FROM_STATEMENT = statement(
    expr=expression('from "[^"]+"'),
    value={
        "type": "array",
        "items": expression(f"(struct|enum|size) {NAME}"),
    },
)
