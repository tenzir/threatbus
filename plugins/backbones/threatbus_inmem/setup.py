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
        "Development Status :: 4 - Beta",
        "Environment :: Plugins",
        "License :: OSI Approved :: BSD License",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Object Brokering",
    ],
    description="A simplistic in-memory backbone for threatbus.",
    entry_points={"threatbus.backbone": ["inmem = threatbus_inmem.plugin"]},
    install_requires=[
        "stix2 >= 3.0",
        "threatbus >= 2021.11.18",
    ],
    keywords=[
        "message broker",
        "threatbus",
        "Threat Bus",
        "threat intelligence",
        "TI",
        "TI dissemination",
    ],
    license="BSD 3-clause",
    long_description=long_description,
    long_description_content_type="text/markdown",
    name="threatbus-inmem",
    packages=["threatbus_inmem"],
    python_requires=">=3.7",
    url="https://github.com/tenzir/threatbus",
    version="2021.11.18",
)
