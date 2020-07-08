#!/bin/dash
pip install -e git+https://github.com/eol-uchile/uchileedxlogin@f2242e57a0c7863e9d46018144bf851b04251b99#egg=uchileedxlogin
pip install -e /openedx/requirements/edx-ucursos

cd /openedx/requirements/edx-ucursos/edxucursos
cp /openedx/edx-platform/setup.cfg .
mkdir test_root
cd test_root/
ln -s /openedx/staticfiles .

cd /openedx/requirements/edx-ucursos/edxucursos

DJANGO_SETTINGS_MODULE=lms.envs.test EDXAPP_TEST_MONGO_HOST=mongodb pytest tests.py
