#!/usr/bin/env python3
"""py-sysinfo - packaging stub.

Deliberately inert: no build hooks, no side effects, nothing to compile.
`pip install .` just records the distribution and exits.
"""
from setuptools import setup

setup(
    name="py-sysinfo",
    version="1.0.1",
    description="Lightweight system information utilities",
    author="Platform Team",
    author_email="platform@example.com",
    python_requires=">=3.8",
    packages=[],
    py_modules=[],
)
