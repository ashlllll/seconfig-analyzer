from setuptools import setup, find_packages

setup(
    name="secconfig-analyzer",
    version="1.0.0",
    description="A Local AI-Augmented Red Team / Blue Team Framework for Configuration Security Analysis",
    author="Qian Zhu",
    author_email="S1034134@lsbf.edu.sg",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.10",
    install_requires=[
        "streamlit==1.31.0",
        "python-dotenv==1.0.0",
        "PyYAML==6.0.1",
        "pandas==2.2.0",
        "numpy==1.26.3",
        "plotly==5.18.0",
        "scipy==1.12.0",
    ],
    extras_require={
        "llm": ["openai==1.12.0"],
        "dev": [
            "black==24.1.1",
            "flake8==7.0.0",
        ],
    },
)
