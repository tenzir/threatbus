from setuptools import setup
import pathlib

plugin_dir = pathlib.Path(__file__).parent.absolute()

with open(f"{plugin_dir}/README.md", "r") as fh:
    long_description = fh.read()

setup(
    author="Tenzir",
    author_email="engineering@tenzir.com",
    classifiers=[
        # https://pypi.org/classifiers/
        "Development Status :: 3 - Alpha",
        "Environment :: Plugins",
        "License :: OSI Approved :: BSD License",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Object Brokering",
    ],
    description="A benchmark backbone for threatbus, that reads a file and provisions its contents.",
    entry_points={"threatbus.backbone": ["file_benchmark = file_benchmark.plugin"]},
    install_requires=[
        "stix2 >= 3.0",
        "threatbus >= 2021.11.18",
    ],
    keywords=["threatbus", "plugin"],
    license="BSD 3-clause",
    long_description=long_description,
    long_description_content_type="text/markdown",
    name="threatbus-file-benchmark",
    packages=["file_benchmark"],
    python_requires=">=3.7",
    url="https://github.com/tenzir/threatbus",
    version="2021.11.18",
)
