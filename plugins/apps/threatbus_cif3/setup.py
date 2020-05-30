from setuptools import setup
import pathlib

plugin_dir = pathlib.Path(__file__).parent.absolute()

with open(f"{plugin_dir}/README.md", "r") as fh:
    long_description = fh.read()

setup(
    author="Michael Davis, derived from work by Tenzir",
    author_email="",
    classifiers=[
        # https://pypi.org/classifiers/
        "Development Status :: 3 - Alpha",
        "Environment :: Plugins",
        "License :: OSI Approved :: BSD License",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Topic :: Scientific/Engineering :: Information Analysis",
        "Topic :: Scientific/Engineering :: Interface Engine/Protocol Translator",
        "Topic :: Security",
        "Topic :: Software Development :: Object Brokering",
        "Topic :: System :: Distributed Computing",
    ],
    description="A plugin to enable indicators to be submitted to CIFv3 in real-time",
    entry_points={"threatbus.app": ["cif3 = threatbus_cif3.plugin"]},
    install_requires=["cifsdk>3.0.0rc4,<4.0"],
    keywords=[
        "cif",
        "cifv3" "cif3",
        "renisac",
        "ren-isac",
        "MISP",
        "threat intelligence",
        "IDS",
        "zeromq",
        "zmq",
        "kafka",
    ],
    license="BSD 3-clause",
    long_description=long_description,
    long_description_content_type="text/markdown",
    name="threatbus-cif3",
    package_dir={"": "plugins/apps"},
    packages=["threatbus_cif3"],
    # packages=find_packages(),
    python_requires=">=3.6",
    url="",
    version="0.1.0",
)
