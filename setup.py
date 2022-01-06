import setuptools
import platform

platform_system = platform.system()

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="blackduck-scan-action",
    version="1.0.11",
    author="Matthew Brady",
    author_email="mbrad@synopsys.com",
    description="Github Action to scan for SCA using Synopsys Black Duck.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/matthewb66/blackduck-scan-action",
    packages=setuptools.find_packages(),
    install_requires=[
        'blackduck>=1.0.4',
        "pyGitHub",
        "aiohttp",
        "blackduck",
        "networkx",
        "requests",
        "semver",
        "lxml",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.0',
    entry_points={
        'console_scripts': ['blackduck-scan-action=bdscan.bdscanaction:main'],
    },
)
