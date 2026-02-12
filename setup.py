#!/usr/bin/env python3
"""Setup script for brig.

This provides full setup() configuration for compatibility with older pip versions.
Configuration is duplicated from pyproject.toml.
"""

from setuptools import setup, find_packages
import os

# Read README for long description if available.
readme_path = os.path.join(os.path.dirname(__file__), "README.md")
long_description = ""
if os.path.exists(readme_path):
    with open(readme_path, "r", encoding="utf-8") as f:
        long_description = f.read()

setup(
    name="brig",
    version="0.1.0",
    description="Secure workload harness for running untrusted code on macOS",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Brig Authors",
    license="MIT",
    python_requires=">=3.9",
    keywords=["security", "containers", "sandbox", "gvisor", "lima"],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: MacOS",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    package_dir={"": "src"},
    packages=find_packages(where="src", include=["brig*", "addons*"]),
    py_modules=["brig_cli", "warden_cli", "brig_subnet_cli"],
    entry_points={
        "console_scripts": [
            "brig=brig_cli:main",
            "warden=warden_cli:main",
            "brig-subnet=brig_subnet_cli:main",
        ],
    },
    install_requires=["pyyaml>=6.0"],
    extras_require={
        "yaml": ["pyyaml>=6.0"],
        "dev": ["pytest>=7.0", "ruff>=0.1.0"],
    },
    url="https://github.com/d0cd/brig",
    project_urls={
        "Documentation": "https://github.com/d0cd/brig/tree/main/docs",
        "Repository": "https://github.com/d0cd/brig",
    },
)
