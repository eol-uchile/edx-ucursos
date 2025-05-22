# EDX UCursos

![Coverage Status](/coverage-badge.svg)

Authentication backend for EOl from Ucursos

# Install

    docker-compose exec cms pip install -e /openedx/requirements/edx-ucursos

# Configuration

If you want redirect to another domain edit *common.py* in *settings* and add domain url, for example "http://my.domain.com".

    EDXUCURSOS_DOMAIN = ""

## TESTS
**Prepare tests:**

- Install **act** following the instructions in [https://nektosact.com/installation/index.html](https://nektosact.com/installation/index.html)

**Run tests:**
- In a terminal at the root of the project
    ```
    act -W .github/workflows/pythonapp.yml
    ```
