# EDX UCursos

![Coverage Status](/coverage-badge.svg)

Authentication backend for EOl from Ucursos

# Install

    docker-compose exec cms pip install -e /openedx/requirements/edx-ucursos

### Adding new translations:

To extract and update any new translatable text, run the update command below. After manually filling in the new translations, run the compile command to update the .mo translation files.

### Commands

**Update**

    docker run -it --rm -w /code -v $(pwd):/code python:3.8 bash
    pip install -r requirements-i18n.in
    make update_translations

**Compile**

    docker run -it --rm -w /code -v $(pwd):/code python:3.8 bash
    pip install -r requirements-i18n.in
    make compile_translations

## TESTS
**Prepare tests:**

- Install **act** following the instructions in [https://nektosact.com/installation/index.html](https://nektosact.com/installation/index.html)

**Run tests:**
- In a terminal at the root of the project
    ```
    act -W .github/workflows/pythonapp.yml
    ```
