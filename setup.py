#!/usr/bin/env python3
"""
Setup script for Provider Discovery Tool
"""
from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
README_PATH = Path(__file__).parent / "README.md"
long_description = README_PATH.read_text(encoding="utf-8") if README_PATH.exists() else ""

# Read requirements
REQUIREMENTS_PATH = Path(__file__).parent / "requirements.txt"
requirements = []
if REQUIREMENTS_PATH.exists():
    with open(REQUIREMENTS_PATH, 'r', encoding='utf-8') as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="provider-discovery",
    version="2.0.0",
    author="Provider Discovery Team",
    author_email="",
    description="Advanced CDN/hosting provider detection with multi-layer analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/provider-discovery",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Networking",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=1.0.0",
        ],
        "web": [
            "streamlit>=1.28.0",
        ],
        "all": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=1.0.0",
            "streamlit>=1.28.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "provider-discovery=provider_discovery.cli:main",
            "provider-discovery-web=provider_discovery.web.app:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords="cdn, hosting, provider, detection, dns, analysis, virustotal",
    project_urls={
        "Bug Reports": "https://github.com/your-org/provider-discovery/issues",
        "Source": "https://github.com/your-org/provider-discovery",
        "Documentation": "https://github.com/your-org/provider-discovery/blob/main/README.md",
    },
)
