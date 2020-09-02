"""Packaging logic for pyruckus."""

from setuptools import setup

with open("README.md", "r") as file:
    long_description = file.read()

setup(
    name="pyruckus",
    version="0.3",
    description="Python API to interact with a Ruckus Unleashed device.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/gabe565/pyruckus",
    author="Gabe Cook",
    author_email="gabe565@gmail.com",
    license="MIT",
    install_requires=["pexpect>=4.0"],
    packages=["pyruckus"],
    zip_safe=True,
    python_requires=">=3.6",
)
