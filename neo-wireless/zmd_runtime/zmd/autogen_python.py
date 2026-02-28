"""Parser for converting ParsedZMD data Python file."""

from .parser_types import ParsedZmd, ParsedZmdStructField
from .raw_zmd_schema import PRIMITIVE_TYPES

c_type_to_python_type = {
    "bool": "bool",
    "char": "str",
    "f32": "float",
    "f64": "float",
    "i16": "int",
    "i32": "int",
    "i64": "int",
    "i8": "int",
    "s16": "int",
    "s32": "int",
    "s64": "int",
    "s8": "int",
    "u16": "int",
    "u32": "int",
    "u64": "int",
    "u8": "int",
    # Add more mappings as needed
}


def parse_c_type(field: ParsedZmdStructField) -> str:
    """Parses a Parsed ZMD Struct field and determines its corresponding Python type.

    This function takes a field from a parsed ZMD struct and maps its C type
    representation to an appropriate Python type. It handles various cases such as:
    - Union types: Returns a union of possible types.
    - Bitfield types: Maps to an integer type.
    - Array types: Maps to a string representation.
    - Packed types: Maps to the corresponding Python type using a predefined mapping.
    - Primitive or unknown types: Defaults to the original type or `Any` if no match is found.

    Args:
        field (ParsedZmdStructField): The parsed field from a ZMD struct.

    Returns:
        str: The Python type corresponding to the given field.
    """
    py_type: str = "Any"

    # More or less all of the "structs" in the parsed zmd are typedDictionaries
    # Handle union types
    """
    name: "data",
        union: [
            {
                name: "motor_temperature_high",
                type: "BringupMotorTemperatures",
                union_name: "data"
            },
            {
                name: "motor_overheated",
                type: "BringupMotorTemperatures",
                union_name: "data"
            }
        ]
    """
    if "union" in field:
        # Handle case where union is a list of structs
        # ie union: [ { name: "foo", type: "Bar" }, { name: "bar", type: "Baz" } ]
        # split on the first space to get the type and drop comments
        py_type = " | ".join(parse_c_type(t).split()[0] for t in field["union"])

    # Handle bitfield types
    elif "bitfield" in field:
        """
        fields: [
            {
            name: "alarms",
            bitfield: [
                {
                    name: "MOTOR_FREEWHEELING"
        },
        """
        # We just map this to an int since that is "closest" python thing to a bitfield
        # without importing c_types or manually doing bit manipulation
        py_type = "int"

    # handle specific type
    elif "type" in field:
        """
        {
            name: "theta_e_voltage",
            type: "f32"
        },
        """
        # Handle array types
        if "[" in field["type"] and "]" in field["type"]:
            """
            {
                name: "theta_e_voltage",
                type: "f32[NUM_ENCODER_SAMPLES]"
            },
            """
            base_type, array_size = field["type"].split("[")
            array_size = array_size.rstrip("]")
            base_type = base_type.strip().split()[-1]  # remove packed if present
            # partially ambiguous if a list[int] is a list of ints or a u8/char to imply a string
            py_type = f"list[{c_type_to_python_type.get(base_type, base_type)}] # {array_size}"

        # Handle packed types(same as regular types)
        # just dump `packed` directive since it does not map to anything in python
        elif "packed" in field["type"]:
            # ie packed f32
            py_type = c_type_to_python_type.get(
                field["type"].split()[-1], field["type"].split()[-1]
            )
        # Just a regular type
        elif field["type"] in PRIMITIVE_TYPES:
            py_type = c_type_to_python_type[field["type"]]

        else:
            # At this point assume it is the name of another Enum
            py_type = field["type"]
    # if we fail to figure it out just yolo make it an Any
    return py_type


def generate_python_code(
    parsed_zmd: ParsedZmd,
    zmd_path: str,
) -> str:
    """Generates Python code from a parsed ZMD file.

    This function takes a parsed ZMD file and generates Python code that includes
    constants, enums, and dataclasses based on the ZMD file's contents. It also
    handles imports for enums, structs, and constants from other ZMD modules.

    ParsedZMD is a dictionary-like object that contains information about sizes
    (constants), enums, structs, and imports. The generated code includes
    appropriate imports, constants, enums, and dataclasses for the parsed ZMD
    file.

    Example:
        parsed_zmd = {
            "sizes": {"MY_CONSTANT": 42},
            "enums": {
                "MyEnum": {
                    "values": {
                        "VALUE1": 1,
                        "VALUE2": 2,
                    }
                }
            },
            "structs": {
                "MyStruct": {
                    "fields": [
                        {"name": "field1", "type": "int"},
                        {"name": "field2", "type": "float"},
                    ]
                }
            },
            "imports": {
                "other_module.zmd": {
                    "enums": ["OtherEnum"],
                    "structs": ["OtherStruct"],
                    "sizes": ["OTHER_CONSTANT"],
                }
            }
        }

    Args:
        parsed_zmd (ParsedZmd): A dictionary-like object representing the parsed
            contents of a ZMD file. It contains information about sizes (constants),
            enums, structs, and imports.
        zmd_path (str): The path to the original ZMD file. This is used for
            documentation purposes in the generated code.

    Returns:
        str: A string containing the generated Python code, including imports,
        constants, enums, and dataclasses.
    """
    enums = []
    const_values = []
    class_names = []
    imports = []
    std_imports = [
        "from dataclasses import dataclass",
        "from enum import Enum",
        "from typing import Any, Union",
    ]
    # get constants from the zmd file
    for name, val in parsed_zmd["sizes"].items():
        const_values.append(f"{name.upper()} = {val}")
    for import_name in parsed_zmd.get("imports", []):
        module_name = import_name.replace("/", ".").removesuffix(".zmd")
        imported_enums: list[str] = sorted(parsed_zmd["imports"][import_name].get("enums", []))
        imported_structs: list[str] = sorted(parsed_zmd["imports"][import_name].get("structs", []))
        imported_constants: list[str] = sorted(parsed_zmd["imports"][import_name].get("sizes", []))
        for enum in imported_enums:
            imports.extend([f"from {module_name} import {enum}"])
        for struct in imported_structs:
            imports.extend([f"from {module_name} import {struct}"])
        for const in imported_constants:
            imports.extend([f"from {module_name} import {const}"])

    for enum_name, enum_data in sorted(parsed_zmd["enums"].items()):
        enum_values = enum_data["values"]

        enums.append(f"class {enum_name}(Enum):")
        # add sorted enum values to the class
        for value_name, value in enum_values.items():
            enums.append(f"    {value_name} = {value}")
        enums.append("\n")

    for struct_name, struct_data in parsed_zmd["structs"].items():
        class_names.append("@dataclass")
        class_names.append(f"class {struct_name}:")
        if len(struct_data["fields"]) == 0:
            class_names.append("    pass")
            continue
        sorted_fields = sorted(struct_data["fields"], key=lambda f: f.get("name", ""))
        for field in sorted_fields:
            # handle case where field has been un-named(was x)
            if "name" not in field:
                continue  # It was un-named
            field_name = field["name"]
            field_type = parse_c_type(field)
            class_names.append(f"    {field_name}: {field_type}")
        class_names.append("\n")
    return (
        f'"""This source was autocoded from {zmd_path}."""\n'
        + ("\n".join(std_imports))
        + "\n"
        + ("\n".join(sorted(imports)))
        + "\n\n\n"
        + ("\n".join(sorted(const_values)))
        + "\n\n\n"
        + ("\n".join(enums))
        + "\n\n\n"
        + ("\n".join(class_names))
    )
