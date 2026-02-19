import itertools
from typing import Dict, Sequence

from .annotations import cull, dump, flatten
from .parser_types import ParsedZmd, ParsedZmdEnum, ParsedZmdStruct
from .raw_zmd_schema import PRIMITIVE_TYPES
from .util import ZmdNode

# The C++ built-in types corresponding to ZMD built-ins.
CPP_TYPES = {
    "bool": "bool",
    "f32": "float",
    "f64": "double",
    "u8": "uint8_t",
    "u16": "uint16_t",
    "u32": "uint32_t",
    "u64": "uint64_t",
    "i8": "int8_t",
    "i16": "int16_t",
    "i32": "int32_t",
    "i64": "int64_t",
}
assert CPP_TYPES.keys() == PRIMITIVE_TYPES

CPP_TYPE_SIZES = {
    "bool": 1,
    "f32": 4,
    "f64": 8,
    "u8": 1,
    "u16": 2,
    "u32": 4,
    "u64": 8,
    "i8": 1,
    "i16": 2,
    "i32": 4,
    "i64": 8,
}
assert CPP_TYPE_SIZES.keys() == CPP_TYPES.keys()

# The namespace of the supporting library functions.
ZIPLINE_MESSAGE_NAMESPACE = "::zipline::common::messages"

# The header portion of a metadata payload.
METADATA_HEADER = "application/x.zipline-message; schema_version=0; struct={struct}"


def autocode_macro_undef(lines, zmd_path, parsed_zmd: ParsedZmd):
    for name in parsed_zmd["sizes"]:
        lines.append(f"#undef {name}")
    return lines


def to_pascal_case(s):
    return "".join(word.capitalize() for word in s.split("_"))


def calc_with_header(len):
    if type(len) == str:
        return f"{len}+6"
    elif len >= 255:
        return len + 6
    else:
        return len + 3


def calc_max_field_size(namespace, field):
    if "type" in field:
        info = field.field_type()

        if info.name in CPP_TYPE_SIZES:
            element_size = CPP_TYPE_SIZES[info.name]
            is_fixed = True
        else:
            element_size = f"ZmTypeInfo<::{namespace}::{info.name}>::kMaxEncodedLength"
            is_fixed = False

        if info.is_array or info.is_vector:
            if type(info.size) == str:
                element_count = f"ZmSize<{namespace}::{info.size}>()"
            else:
                element_count = info.size
        else:
            element_count = 1

        if element_count != 1:
            if is_fixed:
                if type(element_size) == int and type(element_count) == int:
                    return calc_with_header(element_size * element_count)
                else:
                    return calc_with_header(f"{element_size}*{element_count}")
            else:
                return f"({calc_with_header(element_size)})*{element_count}"
        else:
            return calc_with_header(element_size)

    elif "union" in field:
        parts = [
            f"(size_t){calc_max_field_size(namespace, union_field)}"
            for union_field in field.fields()
        ]

        # Union headers are baked into their individual parts
        return "std::max({" + ",\n\t\t\t".join(parts) + "})"

    elif "bitfield" in field:
        return calc_with_header((len(list(field.bits())) + 7) // 8)
    else:
        raise ValueError(f"Field {field['name']} isn't a supported type")


def calc_max_size(namespace, struct):
    namespace_str = "::".join(namespace)
    parts = []
    running_total = 0

    for field in ZmdNode(struct).fields():
        size = calc_max_field_size(namespace_str, field)
        if type(size) == str:
            parts += [size]
        else:
            running_total += size

    parts += [str(running_total)]

    return "+\n\t\t".join(parts)


def autocode_cpp_header(
    zmd_path, parsed_zmd: ParsedZmd, namespace: Sequence[str] = ["zipline", "messages"]
):
    """Generates the body of a c++ header for the given schema.

    Arguments:
        parsed_zmd: The parsed zmd to generate the header for.
        namespace: The namespace to put the autocoded types into.
    """
    # fmt: off
    lines = []
    lines.append(f'// This header was autocoded from {zmd_path}')
    lines.append(u'#pragma once')
    lines.append(u'')
    lines.append(u'#include <array>')
    lines.append(u'#include <optional>')
    lines.append(u'#include <string_view>')
    lines.append(u'')
    lines.append(u'#include <stddef.h>')
    lines.append(u'#include <stdint.h>')
    lines.append(u'')
    lines.append(u'#if defined(ENABLE_JSON_SERDES)')
    lines.append(u'#include "extlib/json/include/nlohmann/json.hpp"')
    lines.append(u'#endif')
    lines.append(u'')
    includes = set([f"{zmd}.h" for zmd in parsed_zmd["imports"]])
    includes.add("lib/zmd/zipline_messages.h")
    for include in sorted(includes):
        lines.append(f'#include "{include}"')
    lines.append(u'')
    lines.append(u'#ifndef __cplusplus')
    lines.append(u'#error "This header is C++ only."')
    lines.append(u'#endif  // __cplusplus')
    lines.append(u'')

    lines = autocode_macro_undef(lines, zmd_path, parsed_zmd)
    lines.append(u'')

    for n in namespace:
        lines.append(f'namespace {n}')
        lines.append(u'{')
    lines.append(u'')
    # Write all sizes
    for name, size in parsed_zmd["sizes"].items():
        lines.append(f'struct {name}')
        lines.append(u'{')
        lines.append(f'    static constexpr size_t kValue = {size};')
        lines.append(u'};')
    lines.append(u'')
    # Write all enum types
    for name, enum in parsed_zmd["enums"].items():
        lines.append(f'enum class {name} : uint8_t')
        lines.append(u'{')
        for value_name, value in enum["values"].items():
            lines.append(f'    {value_name} = {value},')
        lines.append(u'};')
        lines.append(u'')

        # By default nlohmann serializes enums as integers. Use the
        # string representation instead for human readability.
        lines.append(u'#if defined(ENABLE_JSON_SERDES)')
        lines.append(f'NLOHMANN_JSON_SERIALIZE_ENUM({name}, ')
        lines.append(u'{')
        for value_name, value in enum["values"].items():
            lines.append(f'    {{ {name}::{value_name} , "{value_name}" }},')
        lines.append(u"})")
        lines.append(u'#endif')
        lines.append(u'')

    dependent_types_by_struct = {}
    # Write all struct types
    for name, struct in parsed_zmd["structs"].items():
        lines.append(f'struct {name}')
        lines.append(u'{')

        # We would ideally use a set, but we want to preserve the order. So we'll just use a dict with None values.
        dependent_types: Dict[str, None] = {}
        dependent_types_by_struct[name] = dependent_types
        for field in ZmdNode(struct).fields():
            if "type" in field:
                if "name" not in field:
                    continue  # It was un-named
                info = field.field_type()
                if info.name not in CPP_TYPES:
                    dependent_types[info.name] = None
                typename = CPP_TYPES.get(info.name, info.name)
                if info.is_packed:
                    if info.is_scalar:
                        lines.append(f'    {typename} {field["name"]}{{}};  // Packed')
                        continue
                    if info.is_array:
                        if not isinstance(info.size, int):
                            dependent_types[str(info.size)] = None
                        lines.append(f'    std::array<{typename}, {ZIPLINE_MESSAGE_NAMESPACE}::ZmSize<{info.size}>()> {field["name"]}{{}};  // Packed')
                        continue
                    raise ValueError(f'Packed field {field["name"]} of struct {name} isn\'t supported')
                # It's not packed
                if info.is_scalar:
                    lines.append(f'    std::optional<{typename}> {field["name"]};')
                    continue
                if info.is_array:
                    if not isinstance(info.size, int):
                        dependent_types[str(info.size)] = None
                    lines.append(f'    std::optional<std::array<{typename}, {ZIPLINE_MESSAGE_NAMESPACE}::ZmSize<{info.size}>()>> {field["name"]};')
                    continue
                if info.is_vector:
                    if not isinstance(info.size, int):
                        dependent_types[str(info.size)] = None
                    lines.append(f'    {ZIPLINE_MESSAGE_NAMESPACE}::ZmVector<{typename}, {ZIPLINE_MESSAGE_NAMESPACE}::ZmSize<{info.size}>()> {field["name"]};')
                    continue
                raise ValueError(f'Field {field["name"]} of struct {name} isn\'t supported')
            if "union" in field:
                names = []
                types = []
                for union_field in field.fields():
                    if "name" not in union_field:
                        continue  # It was un-named
                    names.append(union_field["name"])
                    if "type" in union_field:
                        info = union_field.field_type()
                        if info.name not in CPP_TYPES:
                            dependent_types[info.name] = None
                        typename = CPP_TYPES.get(info.name, info.name)
                        if info.is_scalar:
                            types.append(typename)
                        elif info.is_array:
                            if not isinstance(info.size, int):
                                dependent_types[str(info.size)] = None
                            types.append(f'std::array<{typename}, {ZIPLINE_MESSAGE_NAMESPACE}::ZmSize<{info.size}>()>')
                        elif info.is_vector:
                            if not isinstance(info.size, int):
                                dependent_types[str(info.size)] = None
                            types.append(f'{ZIPLINE_MESSAGE_NAMESPACE}::ZmVector<{typename}, {ZIPLINE_MESSAGE_NAMESPACE}::ZmSize<{info.size}>()>')
                        else:
                            raise ValueError(f'Union field {union_field["name"]} of union {field["name"]} isn\'t supported')
                    elif "bitfield" in union_field:
                        # Filter out un-named bits, but still count them.
                        bits = [(b["name"], i) for i, b in enumerate(union_field.bits()) if "name" in b]
                        enum_class_name = to_pascal_case(union_field["name"])
                        lines.append(f'    // Bitfield {union_field["name"]}')
                        lines.append(f'    enum class {enum_class_name}')
                        lines.append(u'    {')
                        for b, i in bits:
                            lines.append(f'        {b} = {i},')
                        lines.append(u'        __,  // Marks the end of the bits')
                        lines.append(u'    };')
                        # By default nlohmann serializes enums as integers. Use the
                        # string representation instead for human readability.
                        lines.append(u'#if defined(ENABLE_JSON_SERDES)')
                        lines.append(f'NLOHMANN_JSON_SERIALIZE_ENUM({enum_class_name}, ')
                        lines.append(u'{')
                        for b, i in bits:
                            lines.append(f'    {{ {enum_class_name}::{b} , "{b}" }},')
                        lines.append(u"})")
                        lines.append(u'#endif')
                        lines.append(u'')
                        types.append(f'{ZIPLINE_MESSAGE_NAMESPACE}::ZmBitfield<{enum_class_name}>')
                    else:
                        raise ValueError(f'Union field {union_field["name"]} of union {field["name"]} isn\'t supported')
                enum_class_name = to_pascal_case(field["name"])
                lines.append(f'    // Union {field["name"]}')
                lines.append(f'    enum class {enum_class_name} : typename {ZIPLINE_MESSAGE_NAMESPACE}::SmallestUint<{len(names) + 1}>::Type')
                lines.append(u'    {')
                lines.append(u'        _,  // Marks that the union is invalid')
                for n in names:
                    lines.append(f'        {n},')
                lines.append(u'        __,  // Marks the end of the named union members')
                lines.append(u'    };')
                # By default nlohmann serializes enums as integers. Use the
                # string representation instead for human readability.
                lines.append(u'#if defined(ENABLE_JSON_SERDES)')
                lines.append(f'NLOHMANN_JSON_SERIALIZE_ENUM({enum_class_name}, ')
                lines.append(u'{')
                for n in names:
                    lines.append(f'    {{ {enum_class_name}::{n} , "{n}" }},')
                lines.append(u"})")
                lines.append(u'#endif')
                lines.append(u'')
                lines.append(f'    {ZIPLINE_MESSAGE_NAMESPACE}::ZmUnion<{enum_class_name},')
                for t in types[:-1]:
                    lines.append(f'                                         {t},')
                lines.append(f'                                         {types[-1]}> {field["name"]};')
                continue
            if "bitfield" in field:
                if "name" not in field:
                    continue  # It was un-named
                # Filter out un-named bits, but still count them.
                bits = [(b["name"], i) for i, b in enumerate(field.bits()) if "name" in b]
                enum_class_name = to_pascal_case(field["name"])
                lines.append(f'    // Bitfield {field["name"]}')
                lines.append(f'    enum class {enum_class_name}')
                lines.append(u'    {')
                for b, i in bits:
                    lines.append(f'        {b} = {i},')
                lines.append(u'        __,  // Marks the "overflow" bit')
                lines.append(u'    };')
                # By default nlohmann serializes enums as integers. Use the
                # string representation instead for human readability.
                lines.append(u'#if defined(ENABLE_JSON_SERDES)')
                lines.append(f'NLOHMANN_JSON_SERIALIZE_ENUM({enum_class_name}, ')
                lines.append(u'{')
                for b, i in bits:
                    lines.append(f'    {{ {enum_class_name}::{b} , "{b}" }},')
                lines.append(u"})")
                lines.append(u'#endif')
                lines.append(u'')
                lines.append(f'    {ZIPLINE_MESSAGE_NAMESPACE}::ZmBitfield<{enum_class_name}> {field["name"]};')
                continue
        lines.append(f'}};  // struct {name}')
        lines.append(u'')

    # Generate the json serialization definitions for each struct
    lines.append(u'#if defined(ENABLE_JSON_SERDES)')
    for name, struct in parsed_zmd["structs"].items():
        field_names = []
        for field in ZmdNode(struct).fields():
            if "name" not in field:
                continue  # It was un-named
            field_names.append(field['name'])
        # https://json.nlohmann.me/api/macros/nlohmann_define_type_non_intrusive/
        # "The current implementation is limited to at most 64 member variables."
        # https://flyzipline.atlassian.net/browse/FSW-43674
        if len(field_names) > 64:
            lines.append(f'// Skipping JSON serialization for {name}: too many fields ({len(field_names)})')
            continue
        field_list = ",".join(field_names)
        lines.append(f'NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE({name}, {field_list})')
    lines.append(u'#endif')

    for n in namespace[::-1]:
        lines.append(f'}}  // namespace {n}')
    lines.append(u'')
    lines.append(u'// The following are template specializations and function overloads for serialization.')
    # Write all the serialization stuff at the end of the header.
    for n in ZIPLINE_MESSAGE_NAMESPACE.split("::")[1:]:
        lines.append(f'namespace {n}')
        lines.append(u'{')
    lines.append(u'')
    message_namespace = "::".join(itertools.chain([""], namespace))
    for name, size in parsed_zmd["sizes"].items():
        lines.append(u'template <>')
        lines.append(f'struct ZmTypeInfo<{message_namespace}::{name}>')
        lines.append(u'{')
        size_only: ParsedZmd = {"imports": {}, "sizes": {name: size}, "enums": {}, "structs": {}}
        lines.append(f'    typedef TypeList<{message_namespace}::{name}> Dependencies;')
        lines.append(f'    static constexpr std::string_view kDefinition = R"METADATA({dump(size_only)})METADATA";')
        lines.append(u'};')
        lines.append(u'')

    for name, enum in parsed_zmd["enums"].items():
        lines.append(u'template <>')
        lines.append(f'struct ZmTypeInfo<{message_namespace}::{name}>')
        lines.append(u'{')
        lines.append(u'    static constexpr bool kFixedSize = true;')
        lines.append(f'    static constexpr char kHashType[] = "{enum.get("was", name)}";')
        lines.append(f'    static constexpr size_t kSize = sizeof({message_namespace}::{name});')
        lines.append(f'    static constexpr size_t kMaxEncodedLength = 1;')
        lines.append(f'    static bool Write(const {message_namespace}::{name} &value, char *&buf, size_t &buf_size);')
        lines.append(f'    static bool Read({message_namespace}::{name} &value, const char *&buf, size_t &buf_size);')
        lines.append(f'    typedef TypeList<{message_namespace}::{name}> Dependencies;')
        enum_only: ParsedZmd = {"imports": {}, "sizes": {}, "enums": {name: enum}, "structs": {}}
        lines.append(f'    static constexpr std::string_view kDefinition = R"METADATA({dump(enum_only)})METADATA";')

        lines.append(u'};')
        lines.append(u'')
    for name, struct in parsed_zmd["structs"].items():
        lines.append(u'template <>')
        lines.append(f'struct ZmTypeInfo<{message_namespace}::{name}>')
        lines.append(u'{')
        lines.append(u'    static constexpr bool kFixedSize = false;')
        lines.append(f'    static constexpr char kHashType[] = "{struct.get("was", name)}";')

        max_size = calc_max_size(namespace, struct)
        lines.append(f'    static constexpr size_t kMaxEncodedLength = {max_size};')

        lines.append(f'    static size_t ComputeSize(const {message_namespace}::{name} &value);')
        lines.append(f'    static bool Write(const {message_namespace}::{name} &value, char *&buf, size_t &buf_size);')
        lines.append(f'    static bool Read({message_namespace}::{name} &value, const char *&buf, size_t &buf_size);')
        # We can use a raw string to robustly encode the metadata payload in a readable way.
        lines.append(f'    static constexpr std::string_view kMediaType = "application/x.zipline-message; schema_version=0; struct={name}";')
        lines.append(f'    typedef UniqueTypeList_t<ConcatenateTypeList_t<')
        lines.extend(f'        typename ZmTypeInfo<{message_namespace}::{n}>::Dependencies,' for n in dependent_types_by_struct[name])
        lines.append(f'        TypeList<{message_namespace}::{name}>')
        lines.append(u'    >> Dependencies;')
        struct_only: ParsedZmd = {"imports": {}, "sizes": {}, "enums": {}, "structs": {name: struct}}
        lines.append(f'    static constexpr std::string_view kDefinition = R"METADATA({dump(struct_only)})METADATA";')
        lines.append(u'};')
        lines.append(u'')
    for n in ZIPLINE_MESSAGE_NAMESPACE.split("::")[-1:0:-1]:
        lines.append(f'}}  // namespace {n}')
    # Write a blank line
    lines.append(u'')
    # fmt: on
    return "\n".join(lines)


def autocode_cpp_write_enum(enum: ParsedZmdEnum, message_namespace):
    """Generates the Write function for the given enum.

    Arguments:
        enum: The parsed zmd enum to generate the code for.
        message_namespace: The namespace the message is declared inside of.
    """
    lines = []
    # fmt: off
    typename = f'{message_namespace}::{enum["name"]}'
    lines.append(f'bool ZmTypeInfo<{typename}>::Write(const {typename} &value, char *&buf, size_t &buf_size)')
    lines.append(u'{')
    lines.append(f'    return ZmTypeInfo<std::underlying_type_t<{typename}>>::Write(static_cast<std::underlying_type_t<{typename}>>(value), buf, buf_size);')
    lines.append(u'}')
    # fmt: on
    return lines


def autocode_cpp_read_enum(enum: ParsedZmdEnum, message_namespace):
    """Generates the Read function for the given enum.

    Arguments:
        enum: The parsed zmd enum to generate the code for.
        message_namespace: The namespace the message is declared inside of.
    """
    lines = []
    # fmt: off
    typename = f'{message_namespace}::{enum["name"]}'
    lines.append(f'bool ZmTypeInfo<{typename}>::Read({typename} &value, const char *&buf, size_t &buf_size)')
    lines.append(u'{')
    lines.append(f'    return ZmTypeInfo<std::underlying_type_t<{typename}>>::Read(reinterpret_cast<std::underlying_type_t<{typename}>&>(value), buf, buf_size);')
    lines.append(u'}')
    # fmt: on
    return lines


def autocode_cpp_compute_struct_size(struct: ParsedZmdStruct, message_namespace):
    """Generates the ComputeSize function for the given struct.

    Arguments:
        struct: The parsed zmd struct to generate the code for.
        message_namespace: The namespace the message is declared inside of.
    """
    lines = []
    # fmt: off
    struct_name = f'{message_namespace}::{struct["name"]}'
    lines.append(f'size_t ZmTypeInfo<{struct_name}>::ComputeSize(const {struct_name} &value)')
    lines.append(u'{')
    lines.append(u'    (void)value;  // Just in case there are no fields')
    lines.append(u'    size_t size = 0;')
    for field in ZmdNode(struct).fields():
        if "type" in field:
            if "name" not in field:
                continue  # It was un-named
            info = field.field_type()
            if info.is_packed:
                lines.append(f'    // Packed scalar or array {field["name"]}')
                lines.append(f'    size += ZmSerializedFieldSize(value.{field["name"]});')
                continue
            # It's not packed
            if info.is_scalar or info.is_array:
                lines.append(f'    // Scalar or array {field["name"]}')
                lines.append(f'    if (value.{field["name"]})')
                lines.append(u'    {')
                lines.append(f'        size += ZmSerializedFieldSize(value.{field["name"]}.value());')
                lines.append(u'    }')
                continue
            if info.is_vector:
                lines.append(f'    // Vector {field["name"]}')
                lines.append(f'    if (!value.{field["name"]}.empty())')
                lines.append(u'    {')
                lines.append(f'        size += ZmSerializedFieldSize(value.{field["name"]});')
                lines.append(u'    }')
                continue
            raise ValueError(f'Field {field["name"]} of struct {struct_name} isn\'t supported')
        if "union" in field:
            lines.append(f'    switch (value.{field["name"]}.contains())')
            lines.append(u'    {')
            lines.append(f'        // Union {field["name"]}')
            for union_field in field.fields():
                if "name" not in union_field:
                    continue  # It was un-named
                enum_name = f'{struct_name}::{to_pascal_case(field["name"])}::{union_field["name"]}'
                lines.append(f'        case {enum_name}:')
                lines.append(u'        {')
                if "type" in union_field:
                    lines.append(f'            // Scalar, array or vector {union_field["name"]} in union {field["name"]}')
                    lines.append(f'            size += ZmSerializedFieldSize(*value.{field["name"]}.get<{enum_name}>());')
                elif "bitfield" in union_field:
                    num_bytes = (len(tuple(union_field.bits())) + 7) // 8
                    lines.append(f'            // Bitfield {union_field["name"]} in union {field["name"]}')
                    lines.append(f'            for (size_t num_bytes = {num_bytes};;)')
                    lines.append(u'            {')
                    lines.append(u'                if (num_bytes > 0)')
                    lines.append(u'                {')
                    lines.append(f'                    if (reinterpret_cast<const uint8_t*>(value.{field["name"]}.get<{enum_name}>())[--num_bytes] == 0)')
                    lines.append(u'                    {')
                    lines.append(u'                        continue;')
                    lines.append(u'                    }')
                    lines.append(u'                    ++num_bytes;')
                    lines.append(u'                }')
                    lines.append(f'                size += ZmSerializedHeaderSize(num_bytes) + num_bytes;')
                    lines.append(u'                break;')
                    lines.append(u'            }')
                else:
                    raise ValueError(f'{union_field["name"]} not supported')
                lines.append(f'            break;')
                lines.append(u'        }')
            lines.append(f'        default:')
            lines.append(u'        {')
            lines.append(f'            break;')
            lines.append(u'        }')
            lines.append(u'    }')
            continue
        if "bitfield" in field:
            if "name" not in field:
                continue  # It was un-named
            num_bytes = (len(tuple(field.bits())) + 7) // 8
            lines.append(f'    // Bitfield {field["name"]}')
            lines.append(f'    for (size_t num_bytes = {num_bytes}; num_bytes > 0;)')
            lines.append(u'    {')
            lines.append(f'        if (reinterpret_cast<const uint8_t*>(&value.{field["name"]})[--num_bytes] != 0)')
            lines.append(u'        {')
            lines.append(u'            ++num_bytes;')
            lines.append(f'            size += ZmSerializedHeaderSize(num_bytes) + num_bytes;')
            lines.append(u'            break;')
            lines.append(u'        }')
            lines.append(u'    }')
            continue
    # Empty structs need to be null padded
    lines.append(u'    return size > 0 ? size : 1;')
    lines.append(u'}')
    # fmt: on
    return lines


def autocode_cpp_write_struct(struct: ParsedZmdStruct, message_namespace):
    """Generates the Write function for the given struct.

    Arguments:
        struct: The parsed zmd struct to generate the code for.
        message_namespace: The namespace the message is declared inside of.
    """
    lines = []
    # fmt: off
    struct_name = f'{message_namespace}::{struct["name"]}'
    lines.append(f'bool ZmTypeInfo<{struct_name}>::Write(const {struct_name} &value, char *&buf, size_t &buf_size)')
    lines.append(u'{')
    lines.append(u'    (void)value;  // Just in case there are no fields')
    lines.append(u'    const size_t original_buf_size = buf_size;')
    for field in ZmdNode(struct).fields():
        if "type" in field:
            if "name" not in field:
                continue  # It was un-named
            info = field.field_type()
            typename = CPP_TYPES.get(info.name, f'{message_namespace}::{info.name}')
            hash_value = f'ZmConst<ZmHash("{field.get("was", field["name"])}", ZmTypeInfo<{typename}>::kHashType)>()'
            if info.is_packed:
                lines.append(f'    // Packed scalar or array {field["name"]}')
                lines.append(f'    if (!ZmWriteField(value.{field["name"]}, {hash_value}, buf, buf_size))')
                lines.append(u'    {')
                lines.append(u'        return false;')
                lines.append(u'    }')
                continue
            # It's not packed
            if info.is_scalar or info.is_array:
                lines.append(f'    // Scalar or array {field["name"]}')
                lines.append(f'    if (value.{field["name"]} && !ZmWriteField(value.{field["name"]}.value(), {hash_value}, buf, buf_size))')
                lines.append(u'    {')
                lines.append(u'        return false;')
                lines.append(u'    }')
                continue
            if info.is_vector:
                lines.append(f'    // Vector {field["name"]}')
                lines.append(f'    if (!value.{field["name"]}.empty() && !ZmWriteField(value.{field["name"]}, {hash_value}, buf, buf_size))')
                lines.append(u'    {')
                lines.append(u'        return false;')
                lines.append(u'    }')
                continue
            raise ValueError(f'Field {field["name"]} of struct {struct_name} isn\'t supported')
        if "union" in field:
            lines.append(f'    switch (value.{field["name"]}.contains())')
            lines.append(u'    {')
            lines.append(f'        // Union {field["name"]}')
            enum_class_name = to_pascal_case(field["name"])
            for union_field in field.fields():
                if "name" not in union_field:
                    continue  # It was un-named
                enum_name = f'{struct_name}::{enum_class_name}::{union_field["name"]}'
                lines.append(f'        case {enum_name}:')
                lines.append(u'        {')
                if "type" in union_field:
                    info = union_field.field_type()
                    typename = CPP_TYPES.get(info.name, f'{message_namespace}::{info.name}')
                    hash_value = f'ZmConst<ZmHash("{union_field.get("was", union_field["name"])}", ZmTypeInfo<{typename}>::kHashType)>()'
                    lines.append(f'            // Scalar, array or vector {union_field["name"]} in union {field["name"]}')
                    lines.append(f'            if (!ZmWriteField(*value.{field["name"]}.get<{enum_name}>(), {hash_value}, buf, buf_size))')
                    lines.append(u'            {')
                    lines.append(u'                return false;')
                    lines.append(u'            }')
                elif "bitfield" in union_field:
                    num_bits = len(tuple(union_field.bits()))
                    num_bytes = (num_bits + 7) // 8
                    hash_value = f'ZmConst<ZmHash("{union_field.get("was", union_field["name"])}", ZmTypeInfo<uint8_t>::kHashType)>()'
                    lines.append(f'            // Bitfield {union_field["name"]} in union {field["name"]}')
                    lines.append(f'            for (size_t num_bytes = {num_bytes};;)')
                    lines.append(u'            {')
                    lines.append(u'                if (num_bytes > 0)')
                    lines.append(u'                {')
                    lines.append(f'                    if (reinterpret_cast<const uint8_t*>(value.{field["name"]}.get<{enum_name}>())[--num_bytes] == 0)')
                    lines.append(u'                    {')
                    lines.append(u'                        continue;')
                    lines.append(u'                    }')
                    lines.append(u'                    ++num_bytes;')
                    lines.append(u'                }')
                    lines.append(f'                if (!ZmWriteHeader(num_bytes, {hash_value}, buf, buf_size) || buf_size < num_bytes)')
                    lines.append(u'                {')
                    lines.append(u'                    return false;')
                    lines.append(u'                }')
                    lines.append(u'                for (size_t i = 0; i < num_bytes; ++i)')
                    lines.append(u'                {')
                    lines.append(f'                    if (!ZmTypeInfo<uint8_t>::Write(reinterpret_cast<const uint8_t*>(value.{field["name"]}.get<{enum_name}>())[i], buf, buf_size))')
                    lines.append(u'                    {')
                    lines.append(u'                        return false;')
                    lines.append(u'                    }')
                    lines.append(u'                }')
                    lines.append(u'                break;')
                    lines.append(u'            }')
                else:
                    raise ValueError(f'{union_field["name"]} not supported')
                lines.append(f'            break;')
                lines.append(u'        }')
            lines.append(f'        case {struct_name}::{enum_class_name}::_:')
            lines.append(u'        {')
            lines.append(f'            break;')
            lines.append(u'        }')
            lines.append(f'        default:')
            lines.append(u'        {')
            lines.append(f'            return false;')
            lines.append(u'        }')
            lines.append(u'    }')
            continue
        if "bitfield" in field:
            if "name" not in field:
                continue  # It was un-named
            num_bits = len(tuple(field.bits()))
            num_bytes = (num_bits + 7) // 8
            hash_value = f'ZmConst<ZmHash("{field.get("was", field["name"])}", ZmTypeInfo<uint8_t>::kHashType)>()'
            lines.append(f'    // Bitfield {field["name"]}')
            lines.append(f'    for (size_t num_bytes = {num_bytes}; num_bytes > 0;)')
            lines.append(u'    {')
            lines.append(f'        if (reinterpret_cast<const uint8_t*>(&value.{field["name"]})[--num_bytes] != 0)')
            lines.append(u'        {')
            lines.append(u'            ++num_bytes;')
            lines.append(f'            if (!ZmWriteHeader(num_bytes, {hash_value}, buf, buf_size) || buf_size < num_bytes)')
            lines.append(u'            {')
            lines.append(u'                return false;')
            lines.append(u'            }')
            lines.append(u'            for (size_t i = 0; i < num_bytes; ++i)')
            lines.append(u'            {')
            lines.append(f'                if (!ZmTypeInfo<uint8_t>::Write(reinterpret_cast<const uint8_t*>(&value.{field["name"]})[i], buf, buf_size))')
            lines.append(u'                {')
            lines.append(u'                    return false;')
            lines.append(u'                }')
            lines.append(u'            }')
            lines.append(u'            break;')
            lines.append(u'        }')
            lines.append(u'    }')
            continue
    # Empty structs need to be null padded
    lines.append(u'    // It needs to be null padded')
    lines.append(u'    if (buf_size == original_buf_size)')
    lines.append(u'    {')
    lines.append(u'        if (buf_size == 0)')
    lines.append(u'        {')
    lines.append(u'            return false;')
    lines.append(u'        }')
    lines.append(u'        *buf++ = 0;')
    lines.append(u'        --buf_size;')
    lines.append(u'    }')
    lines.append(u'    return true;')
    lines.append(u'}')
    # fmt: on
    return lines


def autocode_cpp_read_struct(struct: ParsedZmdStruct, message_namespace):
    """Generates the Read function for the given struct.

    Arguments:
        struct: The parsed zmd struct to generate the code for.
        message_namespace: The namespace the message is declared inside of.
    """
    lines = []
    # fmt: off
    struct_name = f'{message_namespace}::{struct["name"]}'
    lines.append(f'bool ZmTypeInfo<{struct_name}>::Read({struct_name} &value, const char *&buf, size_t &buf_size)')
    lines.append(u'{')
    lines.append(u'    (void)value;  // Just in case there are no fields')
    any_packed = any(f.field_type().is_packed for f in ZmdNode(struct).fields() if "info" in f)
    # Detect a null padded struct
    lines.append(u'    // Structs can\'t be empty. Make sure it\'s null padded')
    lines.append(u'    if (buf_size <= 1)')
    lines.append(u'    {')
    lines.append(u'        if (buf_size == 0)')
    lines.append(u'        {')
    lines.append(u'            return false;')
    lines.append(u'        }')
    lines.append(u'        --buf_size;')
    lines.append(u'        if (*buf++ != 0)')
    lines.append(u'        {')
    lines.append(u'            return false;')
    lines.append(u'        }')
    lines.append(f'        return {"false;  // Has packed fields" if any_packed else "true;"}')
    lines.append(u'    }')
    # We need some variables to keep track of whether we've populated packed fields or fixed arrays, and bitfields.
    for field in ZmdNode(struct).fields():
        if "type" in field:
            if "name" not in field:
                continue  # It was un-named
            info = field.field_type()
            if info.is_packed:
                any_packed = True
                if info.is_scalar:
                    lines.append(f'    bool has_{field["name"]} = false;')
                    continue
                if info.is_array:
                    lines.append(f'    size_t num_{field["name"]} = 0;')
                    continue
                raise ValueError(f'Packed field {field["name"]} of struct {struct_name} isn\'t supported')
            if info.is_array:
                lines.append(f'    size_t num_{field["name"]} = 0;')
                continue
        if "union" in field:
            for union_field in field.fields():
                if "name" not in union_field:
                    continue  # It was un-named
                if "type" in union_field:
                    info = union_field.field_type()
                    if info.is_array:
                        lines.append(f'    size_t num_{union_field["name"]} = 0;')
                    continue
                if "bitfield" in union_field:
                    lines.append(f'    size_t num_{union_field["name"]} = 0;')
        if "bitfield" in field:
            if "name" not in field:
                continue  # It was un-named
            lines.append(f'    size_t num_{field["name"]} = 0;')
    # We now need to iterate through the buffer looking for known hashes, and handle the data appropriately.
    lines.append(f'    while (buf_size > 0)')
    lines.append(u'    {')
    lines.append(u'        size_t data_size;')
    lines.append(u'        uint16_t hash;')
    lines.append(u'        if (!ZmReadHeader(data_size, hash, buf, buf_size) || data_size > buf_size)')
    lines.append(u'        {')
    lines.append(u'            return false;')
    lines.append(u'        }')
    lines.append(u'        const char *data_buf = buf;')
    lines.append(u'        (void)data_buf;  // Just in case there are no fields')
    lines.append(u'        buf += data_size;')
    lines.append(u'        buf_size -= data_size;')
    lines.append(u'        switch (hash)')
    lines.append(u'        {')
    # Generate a case for each field
    for field in ZmdNode(struct).fields():
        if "type" in field:
            if "name" not in field:
                continue  # It was un-named
            info = field.field_type()
            typename = CPP_TYPES.get(info.name, f'{message_namespace}::{info.name}')
            hash_value = f'ZmHash("{field.get("was", field["name"])}", ZmTypeInfo<{typename}>::kHashType)'
            if info.is_packed:
                # We need to keep track of whether we've populated packed fields
                if info.is_scalar:
                    lines.append(f'            case {hash_value}:')
                    lines.append(u'            {')
                    lines.append(f'                // Packed scalar {field["name"]}')
                    lines.append(f'                if (has_{field["name"]} ||')
                    lines.append(f'                    !ZmTypeInfo<{typename}>::Read(value.{field["name"]}, data_buf, data_size) ||')
                    lines.append(f'                    data_size > 0)')
                    lines.append(u'                {')
                    lines.append(u'                    return false;')
                    lines.append(u'                }')
                    lines.append(f'                has_{field["name"]} = true;')
                    lines.append(u'                continue;')
                    lines.append(u'            }')
                    continue
                if info.is_array:
                    lines.append(f'            case {hash_value}:')
                    lines.append(u'            {')
                    lines.append(f'                // Packed array {field["name"]}')
                    lines.append(u'                do')
                    lines.append(u'                {')
                    array_size = f'{info.size}'
                    if not array_size.isnumeric():
                        array_size = f'{message_namespace}::{array_size}'
                    lines.append(f'                    if (num_{field["name"]} >= ZmSize<{array_size}>() ||')
                    lines.append(f'                        !ZmTypeInfo<{typename}>::Read(value.{field["name"]}[num_{field["name"]}++], data_buf, data_size))')
                    lines.append(u'                    {')
                    lines.append(u'                        return false;')
                    lines.append(u'                    }')
                    lines.append(u'                } while (data_size > 0);')
                    lines.append(u'                continue;')
                    lines.append(u'            }')
                    continue
                raise ValueError(f'Packed field {field["name"]} of struct {struct_name} isn\'t supported')
            # It's not packed
            if info.is_scalar:
                lines.append(f'            case {hash_value}:')
                lines.append(u'            {')
                lines.append(f'                // Scalar {field["name"]}')
                lines.append(f'                if (value.{field["name"]} ||')
                lines.append(f'                    !ZmTypeInfo<{typename}>::Read(value.{field["name"]}.emplace(), data_buf, data_size) ||')
                lines.append(f'                    data_size > 0)')
                lines.append(u'                {')
                lines.append(u'                    return false;')
                lines.append(u'                }')
                lines.append(u'                continue;')
                lines.append(u'            }')
                continue
            if info.is_array:
                lines.append(f'            case {hash_value}:')
                lines.append(u'            {')
                lines.append(f'                // Array {field["name"]}')
                lines.append(f'                auto &field = value.{field["name"]} ? value.{field["name"]}.value() : value.{field["name"]}.emplace();')
                lines.append(u'                do')
                lines.append(u'                {')
                array_size = f'{info.size}'
                if not array_size.isnumeric():
                    array_size = f'{message_namespace}::{array_size}'
                lines.append(f'                    if (num_{field["name"]} >= ZmSize<{array_size}>() ||')
                lines.append(f'                        !ZmTypeInfo<{typename}>::Read(field[num_{field["name"]}++], data_buf, data_size))')
                lines.append(u'                    {')
                lines.append(u'                        return false;')
                lines.append(u'                    }')
                lines.append(u'                } while (data_size > 0);')
                lines.append(u'                continue;')
                lines.append(u'            }')
                continue
            if info.is_vector:
                lines.append(f'            case {hash_value}:')
                lines.append(u'            {')
                lines.append(f'                // Vector {field["name"]}')
                lines.append(u'                while (data_size > 0)')
                lines.append(u'                {')
                lines.append(f'                    if (!value.{field["name"]}.Resize(value.{field["name"]}.size() + 1) ||')
                lines.append(f'                        !ZmTypeInfo<{typename}>::Read(value.{field["name"]}.back(), data_buf, data_size))')
                lines.append(u'                    {')
                lines.append(u'                        return false;')
                lines.append(u'                    }')
                lines.append(u'                }')
                lines.append(u'                continue;')
                lines.append(u'            }')
                continue
            raise ValueError(f'Field {field["name"]} of struct {struct_name} isn\'t supported')
        if "union" in field:
            union_enum = f'{struct_name}::{to_pascal_case(field["name"])}'
            for union_field in field.fields():
                if "name" not in union_field:
                    continue  # It was un-named
                if "type" in union_field:
                    info = union_field.field_type()
                    typename = CPP_TYPES.get(info.name, f'{message_namespace}::{info.name}')
                    lines.append(f'            case ZmHash("{union_field.get("was", union_field["name"])}", ZmTypeInfo<{typename}>::kHashType):')
                    lines.append(u'            {')
                    if info.is_scalar:
                        lines.append(f'                // Scalar {union_field["name"]} in union {field["name"]}')
                        lines.append(f'                if (value.{field["name"]}.contains() != {union_enum}::_ ||')
                        lines.append(f'                    !ZmTypeInfo<{typename}>::Read(value.{field["name"]}.Set<{union_enum}::{union_field["name"]}>(), data_buf, data_size) ||')
                        lines.append(u'                    data_size > 0)')
                        lines.append(u'                {')
                        lines.append(u'                    return false;')
                        lines.append(u'                }')
                    elif info.is_array:
                        lines.append(f'                // Array {union_field["name"]} in union {field["name"]}')
                        lines.append(f'                if (value.{field["name"]}.contains() != (num_{union_field["name"]} > 0 ? {union_enum}::{union_field["name"]} : {union_enum}::_))')
                        lines.append(u'                {')
                        lines.append(u'                    return false;')
                        lines.append(u'                }')
                        lines.append(f'                auto &field = value.{field["name"]}.Set<{union_enum}::{union_field["name"]}>();')
                        lines.append(u'                do')
                        lines.append(u'                {')
                        array_size = f'{info.size}'
                        if not array_size.isnumeric():
                            array_size = f'{message_namespace}::{array_size}'
                        lines.append(f'                    if (num_{union_field["name"]} >= ZmSize<{array_size}>() ||')
                        lines.append(f'                        !ZmTypeInfo<{typename}>::Read(field[num_{union_field["name"]}++], data_buf, data_size))')
                        lines.append(u'                    {')
                        lines.append(u'                        return false;')
                        lines.append(u'                    }')
                        lines.append(u'                } while (data_size > 0);')
                    elif info.is_vector:
                        lines.append(f'                // Vector {union_field["name"]} in union {field["name"]}')
                        lines.append(f'                switch (value.{field["name"]}.contains())')
                        lines.append(u'                {')
                        lines.append(f'                    case {union_enum}::_:')
                        lines.append(f'                    case {union_enum}::{union_field["name"]}:')
                        lines.append(u'                    {')
                        lines.append(f'                        auto &field = value.{field["name"]}.Set<{union_enum}::{union_field["name"]}>();')
                        lines.append(u'                        while (data_size > 0)')
                        lines.append(u'                        {')
                        lines.append(f'                            if (!field.Resize(field.size() + 1) ||')
                        lines.append(f'                                !ZmTypeInfo<{typename}>::Read(field.back(), data_buf, data_size))')
                        lines.append(u'                            {')
                        lines.append(u'                                return false;')
                        lines.append(u'                            }')
                        lines.append(u'                        }')
                        lines.append(u'                        break;')
                        lines.append(u'                    }')
                        lines.append(u'                    default:')
                        lines.append(u'                    {')
                        lines.append(u'                        return false;')
                        lines.append(u'                    }')
                        lines.append(u'                }')
                    else:
                        raise ValueError(f'Union field {union_field["name"]} of union {field["name"]} isn\'t supported')
                elif "bitfield" in union_field:
                    num_bits = len(tuple(union_field.bits()))
                    num_bytes = (num_bits + 7) // 8
                    lines.append(f'            case ZmHash("{union_field.get("was", union_field["name"])}", ZmTypeInfo<uint8_t>::kHashType):')
                    lines.append(u'            {')
                    lines.append(f'                // Bitfield {union_field["name"]} in union {field["name"]}')
                    lines.append(f'                switch (value.{field["name"]}.contains())')
                    lines.append(u'                {')
                    lines.append(f'                    case {union_enum}::_:')
                    lines.append(f'                    case {union_enum}::{union_field["name"]}:')
                    lines.append(u'                    {')
                    lines.append(f'                        auto &field = value.{field["name"]}.Set<{union_enum}::{union_field["name"]}>();')
                    lines.append(u'                        while (data_size > 0)')
                    lines.append(u'                        {')
                    lines.append(f'                            uint8_t bits;')
                    lines.append(f'                            if (!ZmTypeInfo<uint8_t>::Read(bits, data_buf, data_size))')
                    lines.append(u'                            {')
                    lines.append(u'                                return false;')
                    lines.append(u'                            }')
                    lines.append(f'                            if (num_{union_field["name"]} < {num_bytes})')
                    lines.append(u'                            {')
                    lines.append(f'                                const size_t index = num_{union_field["name"]};')
                    lines.append(f'                                if (++num_{union_field["name"]} == {num_bytes})')
                    lines.append(u'                                {')
                    lines.append(f'                                    bits &= 0x{((1 << (((num_bits - 1) % 8) + 1)) - 1):x};')
                    lines.append(u'                                }')
                    lines.append(f'                                reinterpret_cast<uint8_t*>(&field)[index] = bits;')
                    lines.append(u'                            }')
                    lines.append(u'                        }')
                    lines.append(u'                        break;')
                    lines.append(u'                    }')
                    lines.append(u'                    default:')
                    lines.append(u'                    {')
                    lines.append(u'                        return false;')
                    lines.append(u'                    }')
                    lines.append(u'                }')
                else:
                    raise ValueError(f'Union field {union_field["name"]} of union {field["name"]} isn\'t supported')
                lines.append(u'                continue;')
                lines.append(u'            }')
                continue
        if "bitfield" in field:
            if "name" not in field:
                continue  # It was un-named
            num_bits = len(tuple(field.bits()))
            num_bytes = (num_bits + 7) // 8
            lines.append(f'            case ZmHash("{field.get("was", field["name"])}", ZmTypeInfo<uint8_t>::kHashType):')
            lines.append(u'            {')
            lines.append(f'                // Bitfield {field["name"]}')
            lines.append(u'                while (data_size > 0)')
            lines.append(u'                {')
            lines.append(f'                    uint8_t bits;')
            lines.append(f'                    if (!ZmTypeInfo<uint8_t>::Read(bits, data_buf, data_size))')
            lines.append(u'                    {')
            lines.append(u'                        return false;')
            lines.append(u'                    }')
            lines.append(f'                    if (num_{field["name"]} < {num_bytes})')
            lines.append(u'                    {')
            lines.append(f'                        const size_t index = num_{field["name"]};')
            lines.append(f'                        if (++num_{field["name"]} == {num_bytes})')
            lines.append(u'                        {')
            lines.append(f'                            bits &= 0x{((1 << (((num_bits - 1) % 8) + 1)) - 1):x};')
            lines.append(u'                        }')
            lines.append(f'                        reinterpret_cast<uint8_t*>(&value.{field["name"]})[index] = bits;')
            lines.append(u'                    }')
            lines.append(u'                }')
            lines.append(u'                continue;')
            lines.append(u'            }')
            continue

    # Ignore unknown hashes
    lines.append(u'            default:')
    lines.append(u'            {')
    lines.append(u'                continue;')
    lines.append(u'            }')
    lines.append(u'        }')
    lines.append(u'    }')
    # Check that all packed values made it in the right quantity
    for field in ZmdNode(struct).fields():
        if "type" in field:
            if "name" not in field:
                continue  # It was un-named
            info = field.field_type()
            if info.is_packed:
                # We need to keep track of whether we've populated packed fields
                if info.is_scalar:
                    lines.append(f'    if (!has_{field["name"]})')
                    lines.append(u'    {')
                    lines.append(u'        return false;')
                    lines.append(u'    }')
                    continue
                if info.is_array:
                    array_size = f'{info.size}'
                    if not array_size.isnumeric():
                        array_size = f'{message_namespace}::{array_size}'
                    lines.append(f'    if (num_{field["name"]} != ZmSize<{array_size}>())')
                    lines.append(u'    {')
                    lines.append(u'        return false;')
                    lines.append(u'    }')
                    continue
                raise ValueError(f'Packed field {field["name"]} of struct {struct_name} isn\'t supported')
            if info.is_array:
                array_size = f'{info.size}'
                if not array_size.isnumeric():
                    array_size = f'{message_namespace}::{array_size}'

                lines.append(f'    if (value.{field["name"]} && num_{field["name"]} != ZmSize<{array_size}>())')
                lines.append(u'    {')
                lines.append(u'        return false;')
                lines.append(u'    }')
                continue
        if "union" in field:
            enum_class_name = to_pascal_case(field["name"])
            for union_field in field.fields():
                if "name" not in union_field:
                    continue  # It was un-named
                if "type" in union_field:
                    info = union_field.field_type()
                    if info.is_array:
                        array_size = f'{info.size}'
                        if not array_size.isnumeric():
                            array_size = f'{message_namespace}::{array_size}'
                        lines.append(f'    if (value.{field["name"]}.contains() == {struct_name}::{enum_class_name}::{union_field["name"]} &&')
                        lines.append(f'        num_{union_field["name"]} != ZmSize<{array_size}>())')
                        lines.append(u'    {')
                        lines.append(u'        return false;')
                        lines.append(u'    }')

    # All done
    lines.append(u'    return true;')
    lines.append(u'}')
    # fmt: on
    return lines


def autocode_cpp_source(zmd_path, parsed_zmd, namespace: list = ["zipline", "messages"]):
    """Generates the body of a c++ header for the given parsed zmd.

    Arguments:
        parsed_zmd: The parsed zmd to generate the source for.
        namespace: The namespace to put the autocoded types into.
    """
    lines = []
    # fmt: off
    lines.append(f'// This source was autocoded from {zmd_path}')
    lines.append(f'#include "{zmd_path}.h"')
    lines.append(u'')
    lines.append(u'#include "lib/zmd/zipline_messages.h"')
    lines.append(u'')
    # Write all the serialization stuff at the end of the header.
    for n in ZIPLINE_MESSAGE_NAMESPACE.split("::")[1:]:
        lines.append(f'namespace {n}')
        lines.append(u'{')
    lines.append(u'')
    message_namespace = "::".join(itertools.chain([""], namespace))
    for name, enum in parsed_zmd["enums"].items():
        lines.extend(autocode_cpp_write_enum(enum, message_namespace))
        lines.append(u'')
        lines.extend(autocode_cpp_read_enum(enum, message_namespace))
        lines.append(u'')
    for name, struct in parsed_zmd["structs"].items():
        lines.extend(autocode_cpp_compute_struct_size(struct, message_namespace))
        lines.append(u'')
        lines.extend(autocode_cpp_write_struct(struct, message_namespace))
        lines.append(u'')
        lines.extend(autocode_cpp_read_struct(struct, message_namespace))
        lines.append(u'')
    for n in ZIPLINE_MESSAGE_NAMESPACE.split("::")[-1:0:-1]:
        lines.append(f'}}  // namespace {n}')
    # Write a blank line
    lines.append(u'')
    # fmt: on
    return "\n".join(lines)
