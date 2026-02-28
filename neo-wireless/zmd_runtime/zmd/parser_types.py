"""Type annotations for the ZMD parser output dictionary."""

from typing import Any, Dict, List, TypedDict


class ParsedZmdName(TypedDict, total=False):
    """Any parsed, named item."""

    name: str
    was: str


class ParsedZmdEnum(TypedDict, total=False):
    """A parsed, named enum."""

    name: str
    was: str
    values: Dict[str, int]


class ParsedZmdStructField(TypedDict, total=False):
    """A parsed, named struct field."""

    name: str
    was: str
    type: str
    bitfield: List[ParsedZmdName]
    union: List[Any]
    union_name: str


class ParsedZmdStruct(TypedDict, total=False):
    """A parsed, named struct definition."""

    name: str
    was: str
    fields: List[ParsedZmdStructField]


class ParsedZmdImports(TypedDict):
    """The categorized list of imported symbols."""

    enums: List[str]
    sizes: List[str]
    structs: List[str]


class ParsedZmd(TypedDict):
    """A complete parsed ZMD document."""

    enums: Dict[str, ParsedZmdEnum]
    sizes: Dict[str, int]
    structs: Dict[str, ParsedZmdStruct]
    imports: Dict[str, ParsedZmdImports]
