#!/usr/bin/env python3
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="vulnhound",
    version="0.1.0",
    author="Omaid F.",
    author_email="none@ya.com",
    description="A security vulnerability scanner for code repositories",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/omaidf/vulnhound",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    python_requires=">=3.8",
    install_requires=[
        "torch>=1.7.0",
        "transformers>=4.5.0",
        "tree-sitter>=0.19.0",
        "numpy>=1.19.0",
        "tqdm>=4.50.0",
        "jinja2>=3.0.0",
        "colorama>=0.4.4",
    ],
    entry_points={
        "console_scripts": [
            "vulnhound=vulnhound:main",
        ],
    },
)
