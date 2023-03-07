"""Packaging logic for pyruckus."""

from setuptools import setup

with open("README.md") as file:
    long_description = file.read()

setup(
    name="pyruckus",
    version="0.20",
    description="Python API to interact with Ruckus Unleashed and ZoneDirector devices.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/gabe565/pyruckus",
    author="Gabe Cook",
    author_email="gabe565@gmail.com",
    license="MIT",
    install_requires=[
        "aiohttp>=3.8.4",
        "xmltodict>=0.13.0"
    ],
    packages=["pyruckus"],
    zip_safe=True,
    python_requires=">=3.10",
)
