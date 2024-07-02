from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="PortSeeker",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A port scanning and vulnerability assessment tool leveraging the NVD API.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/portseeker",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=[
        "requests>=2.25.1",
        "python-dotenv>=0.15.0",
        "requests-cache>=0.6.0",
        "tenacity>=7.0.0",
    ],
    extras_require={
        'dev': ['pytest>=6.2.3', 'flake8>=3.9.0'],
    },
    package_data={
        'portseeker': ['data/*.json', 'config/*.yaml'],
    },
    entry_points={
        'console_scripts': [
            'portseeker=portseeker:main',
        ],
    },
)