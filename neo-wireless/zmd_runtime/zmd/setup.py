"""For documentation about python packaging in FlightSystems, check out tools/python_packaging/README.md"""

import package_info  # This is an autocoded module containing package information from the build system
from setuptools import find_namespace_packages, setup

# Find our package and all subpackages contained within it, including any internal flight systems dependencies.
packages = [package_info.PACKAGE_NAME] + find_namespace_packages(
    include=[f"{package_info.PACKAGE_NAME}.*"]
)

setup(
    # The package name and version are managed by the build system.
    name=package_info.CANONICAL_NAME,
    version=package_info.PACKAGE_VERSION,
    # The rest of the metadata can be set normally.
    url="https://github.com/ZiplineTeam/FlightSystems",
    maintainer="Zipline Embedded Team",
    maintainer_email="embedded@flyzipline.com",
    # List any external package dependencies as normal too.
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.1",
        "jsonschema>=4.17.3",
        "pyyaml>=5.1.1",
    ],
    entry_points={
        "console_scripts": [
            "zmd = zipline.zmd.cli:main",
        ],
    },
    # Include all detected packages and their files. Since the package's source directory is procedurally built,
    # there shouldn't be anything that doesn't belong.
    packages=packages,
    package_data={s: ["*"] for s in packages},
)
