#!/bin/dash
pip install -e git+https://github.com/eol-uchile/uchileedxlogin@03fcb1b70324a8e79669d26979df7d59938a7f19#egg=uchileedxlogin
pip install -e /openedx/requirements/edx-ucursos

cd /openedx/requirements/edx-ucursos/edxucursos
cp /openedx/edx-platform/setup.cfg .
mkdir test_root
cd test_root/
ln -s /openedx/staticfiles .

cd /openedx/requirements/edx-ucursos/edxucursos

DJANGO_SETTINGS_MODULE=lms.envs.test EDXAPP_TEST_MONGO_HOST=mongodb pytest tests.py