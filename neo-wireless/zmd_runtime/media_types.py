"""This is the python specification for media types used within FlightSystems.

Documentation: https://flyzipline.atlassian.net/wiki/spaces/EMBEDDED/pages/2636284695/Media+Types+for+Metadata

Media Type RFC: https://www.rfc-editor.org/rfc/rfc6838.html

These media types *must* remain stable across versions. They get serialized into log files, and may be used for
runtime interoporability with instances of software running on different versions.

TODO: Once we're using these across languages, we may need to move them to a YAML file so that they may
be autocoded or something.
"""

# Media types can be prefixed to indicate that their payloads are nested inside an AdminWrapper proto. This
# outer proto wrapper provides a place to attach administrative metadata about the source of the message.
ADMIN_WRAPPER_MEDIA_TYPE_PREFIX = b"admin/"

# The standard JSON media type.
JSON_MEDIA_TYPE = b"application/json"

# Protobufs are encoded in their binary wire format. Their metadata consists of a text-format FileDescriptorSet
# containing enough information to parse the contained protobuf. The media type must have an accompanying message arg
# specifying the name of the message.
PROTOBUF_MEDIA_TYPE = b"application/x.protobuf-filedescset"

# YAML doesn't have an official media type. This seems to be the most common, though.
YAML_MEDIA_TYPE = b"text/yaml"

# Zipline messages are defined in a YAML based schema, typically inside a ZMD file. This media type describes a
# particular struct encoded in the ZMD wire format. The payload may contain only the minimal subset of a definition
# necessary for the struct. Zipline message media types are expected to have accompanying schema_version and struct args,
# then a newline, then yaml payload with the definitions, i.e.
# "application/x.zipline-message; schema_version=0; struct=Foo\n<definitions>"
# This media type is unregistered, so it uses the x. prefix. The data is binary, hence application rather than text.
ZIPLINE_MESSAGE_MEDIA_TYPE = b"application/x.zipline-message"
