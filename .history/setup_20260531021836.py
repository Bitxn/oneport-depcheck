from setuptools import setup, find_packages

setup(
    name="oneport-depcheck",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "packaging",
        "click",
        "rich",
    ],
    entry_points={
        "console_scripts": [
            "depcheck=depcheck.cli:main",
        ],
    },
)