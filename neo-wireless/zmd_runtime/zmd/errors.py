"""Common errors that can be raised by ZMD tools."""


class ZmdParseError(Exception):
    "Raised whenever a ZMD file is invalid but more specific errors (syntax, reference) don't apply."


class ZmdSyntaxError(ZmdParseError):
    "Raised whenever invalid ZMD syntax is encountered."


class ZmdReferenceError(ZmdParseError):
    "Raised when field/type names conflict or are unresolved/undefined."
