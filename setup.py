from setuptools import setup, find_packages

setup(
    name="xtsec",
    version="1.0.0",
    description="Enterprise Web Vulnerability & Penetration Testing Assessment Suite",
    author="Saurabh (@Saura0S)",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
        "beautifulsoup4>=4.11.0",
        "rich>=13.0.0",
        "urllib3>=1.26.0"
    ],
    entry_points={
        "console_scripts": [
            "xtsec=xtsec.cli:main",
        ],
    },
    python_requires=">=3.8",
)