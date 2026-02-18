"""A set of utility functions for working with zipline message "annotations".

Annotations are just regular ZMD, but for the purpose of enabling runtime reflection.
"""

from typing import Dict, List, Tuple

from .parse import parse
from .parser_types import ParsedZmd


def find_collisions(
    zmds: List[str],
) -> Tuple[Dict[str, List[str]], Dict[str, List[str]], Dict[str, List[str]]]:
    """Finds any colliding names in a list of ZMD files.

    Arguments:
        zmds: Paths to zmds to look for collisions in.

    Returns a tuple of duplicate sizes, enums and structs, in the form of dicts keyed by name
    mapping to lists of source ZMD paths.
    """
    sizes: dict[str, list[str]] = {}
    enums: dict[str, list[str]] = {}
    structs: dict[str, list[str]] = {}
    for zmd in zmds:
        with open(zmd, "r") as f:
            parsed_zmd = parse(f)
        for size in parsed_zmd["sizes"]:
            sizes.setdefault(size, []).append(zmd)
        for enum in parsed_zmd["enums"]:
            enums.setdefault(enum, []).append(zmd)
        for struct in parsed_zmd["structs"]:
            structs.setdefault(struct, []).append(zmd)
    duplicate_sizes = {size: zmds for size, zmds in sizes.items() if len(zmds) > 1}
    duplicate_enums = {enum: zmds for enum, zmds in enums.items() if len(zmds) > 1}
    duplicate_structs = {struct: zmds for struct, zmds in structs.items() if len(zmds) > 1}
    return duplicate_sizes, duplicate_enums, duplicate_structs
