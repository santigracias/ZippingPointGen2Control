"""Command line utility for processing Zipline Message Definition files."""

import os
import sys

import click
import yaml

from . import annotations
from .autogen_python import generate_python_code
from .collisions import find_collisions
from .cpp import autocode_cpp_header, autocode_cpp_source
from .errors import ZmdParseError, ZmdReferenceError, ZmdSyntaxError
from .parse import parse


@click.group()
def main():
    pass


@main.command()
@click.argument("zmd_file", type=click.File("r"))
def lint(zmd_file):
    """Validate the given ZMD_FILE for syntax or semantic errors."""
    # Just try and parse the file and bubble up any parsing/syntax errors.
    # Will check the document for syntax errors as well as things like duplicate names, invalid types, etc.
    try:
        parse(zmd_file.read())
    except (ZmdParseError, ZmdSyntaxError, ZmdReferenceError):
        # Disable the distracting traceback. We just want the final error.
        # If someone does really want the traceback, it's available in the `debug` command output.
        sys.tracebacklimit = 0
        raise


@main.command()
@click.argument("zmd_file", type=click.File("r"))
def debug(zmd_file):
    """Dump debug info about the given ZMD_FILE."""
    parsed = parse(zmd_file.read())
    click.echo(yaml.safe_dump(parsed))


@main.command()
@click.argument("zmd_file", type=click.File("r"))
@click.option("--import-root", "-i", default=".", type=click.Path())
@click.option("--output-root", "-o", default=".", type=click.Path())
@click.option("--namespace", "-n", default="", type=click.STRING)
def cpp(zmd_file, import_root, output_root, namespace=["zipline", "messages"]):
    """Autocode a C++ interface for the given ZMD_FILE."""
    full_namespace = ["zipline", "messages"]
    if namespace != "":
        full_namespace.append(namespace)
    parsed_zmd = parse(zmd_file.read())
    zmd_path = os.path.relpath(zmd_file.name, start=import_root)
    header = autocode_cpp_header(zmd_path, parsed_zmd, full_namespace)
    source = autocode_cpp_source(zmd_path, parsed_zmd, full_namespace)
    os.makedirs(os.path.join(output_root, os.path.dirname(zmd_path)), exist_ok=True)
    with open(os.path.join(output_root, f"{zmd_path}.h"), "w") as out:
        out.write(header)
    with open(os.path.join(output_root, f"{zmd_path}.cpp"), "w") as out:
        out.write(source)


@main.command()
@click.argument("zmd_file", type=click.File("r"))
@click.option("--import-root", "-i", default=".", type=click.Path())
@click.option("--output-root", "-o", default=".", type=click.Path())
def python(zmd_file, import_root, output_root, namespace=["zipline", "messages"]):
    """Autocode a Python interface for the given ZMD_FILE."""
    filename = os.path.basename(zmd_file.name.replace(".zmd", ""))
    parsed_zmd = parse(zmd_file.read())
    zmd_path = os.path.relpath(zmd_file.name, start=import_root)
    py_file = generate_python_code(parsed_zmd, zmd_path)
    with open(os.path.join(output_root, f"{filename}.py"), "w") as out:
        out.write(py_file)


@main.command()
@click.argument("zmd_file", type=click.File("r"))
@click.option("--import-root", "-i", default=".", type=click.Path())
@click.option("--output", "-o", default=sys.stdout, type=click.File("w"))
def flatten(zmd_file, import_root, output):
    """Outputs flattened annotations for the given ZMD_FILE."""
    output.write(annotations.dump(annotations.flatten(parse(zmd_file), import_root)))


@main.command()
@click.argument("zmd_file", type=click.File("r"))
@click.argument("items", type=str, nargs=-1)
@click.option("--output", "-o", default=sys.stdout, type=click.File("w"))
def cull(zmd_file, items, output):
    """Culls ZMD_FILE down to only contain the specified items."""
    output.write(annotations.dump(annotations.cull(parse(zmd_file), items)))


@main.command()
@click.argument("zmd_files", nargs=-1, type=str)
@click.option("--output", "-o", default=sys.stdout, type=click.File("w"))
def collisions(zmd_files, output):
    """Finds colliding names within one or more ZMD_FILES."""

    def pretty_write(output, header, collisions):
        for name, paths in collisions.items():
            output.write(f"{header} {name}:\n")
            for path in paths:
                output.write(f"    {path}\n")

    sizes, enums, structs = find_collisions(zmd_files)
    pretty_write(output, "size", sizes)
    pretty_write(output, "enum", enums)
    pretty_write(output, "struct", structs)

    if sizes or enums or structs:
        sys.exit(1)
