import setuptools

setuptools.setup(
    name="edxucursos",
    version="0.0.1",
    author="Luis Santana",
    author_email="luis.santana@uchile.cl",
    description="Authentication backend for EOl from Ucursos",
    long_description="Authentication backend for EOl from Ucursos",
    url="https://eol.uchile.cl",
    packages=setuptools.find_packages(),
    install_requires=["unidecode>=1.1.1"],
    classifiers=[
        "Programming Language :: Python :: 2",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points={
        "lms.djangoapp": ["edxucursos = edxucursos.apps:EdxUCursosConfig"]},
)
