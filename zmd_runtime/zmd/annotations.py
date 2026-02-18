"""A set of utility functions for working with zipline message "annotations".

Annotations are just regular ZMD, but for the purpose of enabling runtime reflection.
"""

import itertools
import os
from typing import Any, Dict, Iterable, Set

import yaml

from .errors import ZmdReferenceError
from .parse import parse
from .parser_types import ParsedZmd, ParsedZmdImports
from .raw_zmd_schema import PRIMITIVE_TYPES
from .util import ZmdNode
from .validate import validate_parsed_zmd_schema, validate_raw_zmd_schema


# Override yaml's behavior to not sort dicts.
class _YamlDumper(yaml.SafeDumper):
    def represent_dict_preserve_order(self, data):
        return self.represent_dict(data.items())


_YamlDumper.add_representer(dict, _YamlDumper.represent_dict_preserve_order)


def _dump_field(field: ZmdNode) -> Dict[str, Any]:
    """Dumps an individual field, suitable for passing into yaml.dump."""
    was_string = f" (was {field['was']})" if "was" in field else ""
    field_name = f"{field['name']}{was_string}"
    if "type" in field:
        return {field_name: field["type"]}
    elif "union" in field:
        return {
            field_name: [
                _dump_field(union_field) for union_field in field.fields() if "name" in union_field
            ]
        }
    elif "bitfield" in field:
        return {
            field_name: [
                f"{b.get('name', '(was {})'.format(b.get('was', '')))}" for b in field.bits()
            ]
        }
    raise ValueError


def dump(parsed_zmd: ParsedZmd) -> str:
    """Generates YAML for the given parsed ZMD.

    Arguments:
        parsed_zmd: The parsed ZMD to generate YAML for.
    """
    raw_zmd: Dict = {}
    for import_path, imported_stuff in parsed_zmd["imports"].items():
        imports = []
        imports.extend([f"size {s}" for s in imported_stuff["sizes"]])
        imports.extend([f"enum {e}" for e in imported_stuff["enums"]])
        imports.extend([f"struct {s}" for s in imported_stuff["structs"]])
        raw_zmd[f'from "{import_path}"'] = imports
    for name, size in parsed_zmd["sizes"].items():
        raw_zmd[f"size {name}"] = size
    for name, enum in parsed_zmd["enums"].items():
        was_string = f" (was {enum['was']})" if "was" in enum else ""
        raw_zmd[f"enum {name}{was_string}"] = enum["values"]
    for name, struct in parsed_zmd["structs"].items():
        was_string = f" (was {struct['was']})" if "was" in struct else ""
        raw_zmd[f"struct {name}{was_string}"] = [
            _dump_field(f) for f in ZmdNode(struct).fields() if "name" in f
        ]
    validate_raw_zmd_schema(raw_zmd)
    return yaml.dump(raw_zmd, Dumper=_YamlDumper, width=float("inf"))


def flatten(parsed_zmd: ParsedZmd, import_root: str) -> ParsedZmd:
    """Flattens a parsed ZMD definition, recursively following all its imports.

    The resulting flattened ZMD is culled down to only include the minimum necessary to represent the top level
    sizes, enum and struct types.

    Note: the returned schema is not a deep copy and references back into the passed in schema.

    Arguments:
        parsed_zmd: The parsed ZMD to flatten.
        input_root: The root path to load imports relative from.

    Returns the flattened ZMD.
    """
    # We'll load everything into memory, then cull it down at the end.
    # Start with what we have already.
    flattened_zmd: ParsedZmd = {
        "sizes": parsed_zmd["sizes"],
        "enums": parsed_zmd["enums"],
        "structs": parsed_zmd["structs"],
        "imports": {},
    }
    imports = set(parsed_zmd["imports"])
    while imports:
        with open(os.path.join(import_root, imports.pop())) as f:
            imported = parse(f)
        imports.update(imported["imports"])
        imported["imports"] = {}
        # Update imported then take it's dict. This tends to output slightly more readable output,
        # since stuff will tend to be declared before it is used (dicts are ordered in modern python).
        imported["sizes"].update(flattened_zmd["sizes"])
        flattened_zmd["sizes"] = imported["sizes"]
        imported["enums"].update(flattened_zmd["enums"])
        flattened_zmd["enums"] = imported["enums"]
        imported["structs"].update(flattened_zmd["structs"])
        flattened_zmd["structs"] = imported["structs"]
    # Cull it down
    culled_zmd = cull(
        flattened_zmd,
        parsed_zmd["sizes"].keys() | parsed_zmd["enums"].keys() | parsed_zmd["structs"].keys(),
    )
    # Make sure it's all valid
    validate_parsed_zmd_schema(culled_zmd)
    return culled_zmd


def cull(parsed_zmd: ParsedZmd, items: Iterable[str]) -> ParsedZmd:
    """Culls a schema down to the minimum needed to describe the specified items.

    Note: the returned schema is not a deep copy and references back into the passed in schema.

    Arguments:
        parsed_zmd: The parsed ZMD to cull.
        sizes: The sizes to keep
        enums: The enums to keep
        structs: The structs to keep

    Returns the culled ZMD.
    """
    items_set = set(items)
    # We can't use sets directly because we want to preserve the order of things. Do everything in reverse so that
    # we can append during all the iteration.
    required_sizes = [s for s in parsed_zmd["sizes"] if s in items_set][::-1]
    required_enums = [e for e in parsed_zmd["enums"] if e in items_set][::-1]
    required_structs = [s for s in parsed_zmd["structs"] if s in items_set][::-1]
    if missing_items := items_set.difference(required_sizes, required_enums, required_structs):
        raise ValueError(f"Can't cull items {missing_items} not in ZMD")
    # We need to iterate over every required struct, recursively looking for dependencies.
    structs_to_scan = list(required_structs)
    while structs_to_scan:
        struct_name = structs_to_scan.pop()
        for f in ZmdNode(parsed_zmd["structs"][struct_name]).fields():
            if "bitfield" in f:
                continue  # No fields to iterate over
            # We only care about types, whether or not they're in a union.
            for field in [f] if "type" in f else f.fields():
                if "type" not in field:
                    continue
                info = field.field_type()
                field_size = info.size
                if not (field_size is None or isinstance(field_size, int)):
                    required_sizes.append(field_size)
                if info.name in PRIMITIVE_TYPES:
                    continue
                # It's a custom type.
                if info.name in parsed_zmd["enums"]:
                    required_enums.append(info.name)
                elif info.name in parsed_zmd["structs"]:
                    if info.name not in required_structs:
                        structs_to_scan.append(info.name)  # We need to scan it
                    required_structs.append(info.name)
                else:
                    # It must be imported. We still need to find it to know whether it's an enum or a struct.
                    for imported in parsed_zmd["imports"].values():
                        if info.name in imported["enums"]:
                            required_enums.append(info.name)
                            break
                        if info.name in imported["structs"]:
                            required_structs.append(info.name)
                            break
    # Now we can go through every required thing and add it, whether it's imported or not.
    culled_zmd: ParsedZmd = {"imports": {}, "sizes": {}, "enums": {}, "structs": {}}
    # We don't want to duplicate items
    processed_items = set()
    for key in ["sizes", "enums", "structs"]:
        for name in {
            "sizes": required_sizes[::-1],
            "enums": required_enums[::-1],
            "structs": required_structs[::-1],
        }[key]:
            if name in processed_items:
                continue
            processed_items.add(name)
            try:
                culled_zmd[key][name] = parsed_zmd[key][name]  # type: ignore[literal-required]
            except KeyError:
                for imported_path, imported in parsed_zmd["imports"].items():
                    if name in imported[key]:  # type: ignore[literal-required]
                        if imported_path not in culled_zmd["imports"]:
                            culled_zmd["imports"][imported_path] = {
                                "sizes": [],
                                "enums": [],
                                "structs": [],
                            }
                        culled_zmd["imports"][imported_path][key].append(name)  # type: ignore[literal-required]
                        break
    validate_parsed_zmd_schema(culled_zmd)
    return culled_zmd


def merge_named_zmds(parsed_zmds: Dict[str, ParsedZmd], import_root: str) -> ParsedZmd:
    """
    Merges unflattened `ParsedZmd`s into a single `ParsedZmd`. The input `ParsedZmds`
    are each associated with a file path. This enables checking for name collisions.

    Arguments:
    parsed_zmds : Dict[str, ParsedZmd]
        A dict mapping from file paths to the associated `ParsedZmd`
    import_root : str
        The path that imports in all of the `ParsedZmd`s are relative to. `parsed_zmd`'s
        keys should also be relative to this path.
    """
    return _NamedZmdMerger()._merge_named_zmds(parsed_zmds, import_root)


class _NamedZmdMerger:
    ITEM_CATEGORIES: Set[str] = {"enums", "sizes", "structs"}

    def _merge_named_zmds(self, parsed_zmds: Dict[str, ParsedZmd], import_root: str) -> ParsedZmd:
        """
        Implementation of `merge_named_zmds()` free function. This should not be called
        directly

        Arguments:
        parsed_zmds : Dict[str, ParsedZmd]
            A dict mapping from file paths to the associated `ParsedZmd`
        import_root : str
            The path that imports in all of the `ParsedZmd`s are relative to.
            `parsed_zmd`'s keys should also be relative to this path.
        """
        self._item_define_paths: Dict[str, Dict[str, str]] = {}
        for item_category in {"enums", "sizes", "structs"}:
            self._item_define_paths[item_category] = {}
        self._item_import_edges: Dict[str, Dict[str, _ImportEdge]] = {}

        # We don't declare this a `ParsedZmd` here to ease looping over the categories;
        # MyPy requires literals to access a TypedDict but in this case, the operations
        # we perform over the TypeDict are generic over the key.
        self._merged_parsed_zmd: Dict[str, Any] = {
            "enums": {},
            "sizes": {},
            "structs": {},
            "imports": {},
        }

        # We need to add the defined items before adding the imported items because we
        # check for define-import collisions when adding the imported items.
        self._add_defined_items(parsed_zmds)
        self._add_imported_items(parsed_zmds)

        merged_parsed_zmd: ParsedZmd = {
            "enums": self._merged_parsed_zmd["enums"],
            "sizes": self._merged_parsed_zmd["sizes"],
            "structs": self._merged_parsed_zmd["structs"],
            "imports": self._merged_parsed_zmd["imports"],
        }
        return merged_parsed_zmd

    def _add_defined_items(self, parsed_zmds: Dict[str, ParsedZmd]):
        """
        Helper method that adds each defined item of each individual `ParsedZmd` to the
        combined zmd. It also updates a mapping from items to origin file so that
        collisions can be detected.
        """
        for (
            file,
            parsed_zmd,
        ) in parsed_zmds.items():
            for item_instance_key in parsed_zmd["enums"].keys():
                self._record_define_path("enums", item_instance_key, file)
            self._merged_parsed_zmd["enums"].update(parsed_zmd["enums"])

            for item_instance_key in parsed_zmd["sizes"].keys():
                self._record_define_path("sizes", item_instance_key, file)
            self._merged_parsed_zmd["sizes"].update(parsed_zmd["sizes"])

            for item_instance_key in parsed_zmd["structs"].keys():
                self._record_define_path("structs", item_instance_key, file)
            self._merged_parsed_zmd["structs"].update(parsed_zmd["structs"])

    def _add_imported_items(self, parsed_zmds: Dict[str, ParsedZmd]):
        """
        Helper method that adds each imported item that is not defined in any of the
        zmds being combined. This will throw an exception if the same item is imported
        from multiple sources or if an item is defined in one of the combined zmds but
        also imported from a different source.
        """
        for item_category in self.ITEM_CATEGORIES:
            self._item_import_edges[item_category] = {}

        for (
            file,
            parsed_zmd,
        ) in parsed_zmds.items():
            for import_src, imported_items in parsed_zmd["imports"].items():
                if (
                    import_src not in parsed_zmds.keys()
                    and import_src not in self._merged_parsed_zmd["imports"].keys()
                ):
                    self._merged_parsed_zmd["imports"][import_src] = {}
                    for item_category in self.ITEM_CATEGORIES:
                        self._merged_parsed_zmd["imports"][import_src][item_category] = []
                for item in imported_items["enums"]:
                    self._add_imported_item("enums", item, import_src, file)
                for item in imported_items["sizes"]:
                    self._add_imported_item("sizes", item, import_src, file)
                for item in imported_items["structs"]:
                    self._add_imported_item("structs", item, import_src, file)

    def _record_define_path(self, item_category: str, item_name: str, item_src: str):
        """
        Helper method that keeps track of where items were defined from and throws an
        exception if an item is defined in multiple sources.
        """
        if item_name in self._item_define_paths[item_category]:
            previous_encountered_file = self._item_define_paths[item_category][item_name]
            raise ZmdReferenceError(
                f"""
                    {item_category} {item_name} encountered in multiple times including
                    in {previous_encountered_file} and{item_src}
                """
            )
        else:
            self._item_define_paths[item_category][item_name] = item_src

    def _add_imported_item(
        self,
        item_category: str,
        item_name: str,
        import_src: str,
        import_dest: str,
    ):
        if item_name in self._item_define_paths[item_category]:
            definition_src = self._item_define_paths[item_category][item_name]
            if definition_src != import_src:
                raise ZmdReferenceError(
                    f"""
                        {item_category} {item_name} defined in {definition_src} then
                        imported from {import_src} to {import_dest}
                    """
                )
        elif item_name in self._item_import_edges[item_category]:
            previous_item_import_edge: _ImportEdge = self._item_import_edges[item_category][
                item_name
            ]
            if import_src != previous_item_import_edge.src:
                raise ZmdReferenceError(
                    f"""
                        {item_category} {item_name} imported from two different sources.
                         First imported from {previous_item_import_edge.src} to
                        {previous_item_import_edge.dest} then imported from {import_src}
                         to {import_dest}.
                    """
                )
        else:
            self._item_import_edges[item_category][item_name] = _ImportEdge(import_src, import_dest)
            self._merged_parsed_zmd["imports"][import_src][item_category].append(item_name)


class _ImportEdge:
    """
    Helper class for `merge_and_flatten()` that simply stores the names of the path a
    zmd item is imported from and the path of the zmd that is importing the item.
    """

    def __init__(self, src: str, dest: str):
        self.src = src
        self.dest = dest
