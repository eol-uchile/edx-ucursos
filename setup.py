import setuptools

setuptools.setup(
    name="edxucursos",
    version="0.0.1",
    author="Felipe Espinoza",
    author_email="felipe.espinoza.r@uchile.cl",
    description="Authentication backend for Chile edxucursos",
    long_description="Authentication backend for Chile edxucursos",
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
