# EDX UCursos

Authentication backend for EOl from Ucursos

# Install

    docker-compose exec cms pip install -e /openedx/requirements/edx-ucursos

# Configuration

If you want redirect to another domain edit *common.py* in *settings* and add domain url, for example "http://my.domain.com".

    EDXCURSOS_DOMAIN = ""

## TESTS
**Prepare tests:**

    > cd .github/
    > docker-compose run lms /openedx/requirements/edx-ucursos/.github/test.sh
