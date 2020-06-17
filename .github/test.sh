#!/bin/dash
pip install -e git+https://github.com/eol-uchile/uchileedxlogin@2cbd7a788833040385f8f9f12e557b790c2f0a53#egg=uchileedxlogin
pip install -e /openedx/requirements/edx-ucursos

cd /openedx/requirements/edx-ucursos/edxucursos
cp /openedx/edx-platform/setup.cfg .
mkdir test_root
cd test_root/
ln -s /openedx/staticfiles .

cd /openedx/requirements/edx-ucursos/edxucursos

DJANGO_SETTINGS_MODULE=lms.envs.test EDXAPP_TEST_MONGO_HOST=mongodb pytest tests.py