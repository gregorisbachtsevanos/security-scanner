from setuptools import setup, find_packages

setup(
    name="secscan",
    version="0.1.0",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.9",
    install_requires=[
        "click>=8.1.3",
        "httpx>=0.27.0",
        "rich>=13.7.1",
        "idna>=3.7",
    ],
    entry_points={
        "console_scripts": [
            "secscan=secscan.cli:main",
        ]
    },
    include_package_data=True,
)
