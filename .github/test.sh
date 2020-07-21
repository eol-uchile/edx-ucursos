#!/bin/dash
pip install -e git+https://github.com/eol-uchile/uchileedxlogin@4824135667a8420bfe653f1319347b975aca5a19#egg=uchileedxlogin
pip install -e /openedx/requirements/edx-ucursos

cd /openedx/requirements/edx-ucursos/edxucursos
cp /openedx/edx-platform/setup.cfg .
mkdir test_root
cd test_root/
ln -s /openedx/staticfiles .

cd /openedx/requirements/edx-ucursos/edxucursos

DJANGO_SETTINGS_MODULE=lms.envs.test EDXAPP_TEST_MONGO_HOST=mongodb pytest tests.py
