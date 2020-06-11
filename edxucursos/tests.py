#!/usr/bin/env python
# -*- coding: utf-8 -*-
from mock import patch, Mock, MagicMock
from collections import namedtuple
from django.urls import reverse
from django.test import TestCase, Client
from django.test import Client
from django.conf import settings
from django.contrib.auth.models import Permission, User
from django.contrib.contenttypes.models import ContentType
from urlparse import parse_qs
from openedx.core.lib.tests.tools import assert_true
from opaque_keys.edx.locator import CourseLocator
from student.tests.factories import CourseEnrollmentAllowedFactory, UserFactory, CourseEnrollmentFactory
from xmodule.modulestore.tests.factories import CourseFactory, ItemFactory
from xmodule.modulestore import ModuleStoreEnum
from xmodule.modulestore.tests.django_utils import ModuleStoreTestCase
from openedx.core.djangoapps.content.course_overviews.models import CourseOverview
from student.roles import CourseInstructorRole, CourseStaffRole
import re
import json
import urlparse
import time
import uuid
from .views import EdxUCursosLoginRedirect, EdxUCursosCallback
from models import EdxUCursosMapping

class TestRedirectView(TestCase):

    def setUp(self):
        self.client_login = Client()
        self.client = Client()
        self.user = UserFactory(
            username='student',
            password='12345',
            email='student@edx.org')

    @patch('requests.get')
    def test_login(self, get):
        from uchileedxlogin.models import EdxLoginUser
        EdxLoginUser.objects.create(user=self.user, run='0000000108')
        get.side_effect = [
            namedtuple(
                "Request",
                [
                    "status_code",
                    "text"])(
                200,
                json.dumps(
                    {
                        "pers_id": 10,
                        "permisos": {
                            "PROFESOR": 1,
                            "VER": 1,
                            "DEV": 1},
                        "lang": "es",
                        "theme": None,
                        "css": "https:\/\/www.u-cursos.cl\/d\/css\/style_externo_v7714.css",
                        "time": time.time(),
                        "mod_id": "eol",
                        "gru_id": "curso.372168",
                        "grupo": {
                                "base": "demo",
                                "anno": "2020",
                                "semestre": "0",
                                "codigo": "CV2020",
                                "seccion": "1",
                                "nombre": "Curso de prueba Virtual"}}))]

        result = self.client.get(
            reverse('edxucursos-login:login'),
            data={
                'ticket': 'testticket'})

        self.assertIn(
            'http://testserver/edxucursos/callback?token=',
            result._container[0])

    @patch('requests.get')
    def test_login_wrong_or_none_ticket(self, get):
        from uchileedxlogin.models import EdxLoginUser
        EdxLoginUser.objects.create(user=self.user, run='0000000108')
        get.side_effect = [
            namedtuple(
                "Request",
                [
                    "status_code",
                    "text"])(
                200, 'null')]

        result = self.client.get(
            reverse('edxucursos-login:login'),
            data={
                'ticket': 'wrongticket'})
        self.assertEquals(result.status_code, 404)
        self.assertEquals(
            result._container[0],
            'Error with ucursos api - ticket')

    @patch('requests.get')
    def test_login_caducity_ticket(self, get):
        from uchileedxlogin.models import EdxLoginUser
        EdxLoginUser.objects.create(user=self.user, run='0000000108')
        get.side_effect = [
            namedtuple(
                "Request",
                [
                    "status_code",
                    "text"])(
                200,
                json.dumps(
                    {
                        "pers_id": 10,
                        "permisos": {
                            "PROFESOR": 1,
                            "VER": 1,
                            "DEV": 1},
                        "lang": "es",
                        "theme": None,
                        "css": "https:\/\/www.u-cursos.cl\/d\/css\/style_externo_v7714.css",
                        "time": 1591280309,
                        "mod_id": "eol",
                        "gru_id": "curso.372168",
                        "grupo": {
                                "base": "demo",
                                "anno": "2020",
                                "semestre": "0",
                                "codigo": "CV2020",
                                "seccion": "1",
                                "nombre": "Curso de prueba Virtual"}}))]

        result = self.client.get(
            reverse('edxucursos-login:login'),
            data={
                'ticket': 'testticket'})
        self.assertEquals(result.status_code, 404)
        self.assertEquals(result._container[0], 'Expired ticket')

    @patch('requests.get')
    def test_login_user_no_exists(self, get):
        get.side_effect = [
            namedtuple(
                "Request",
                [
                    "status_code",
                    "text"])(
                200,
                json.dumps(
                    {
                        "pers_id": 10,
                        "permisos": {
                            "PROFESOR": 1,
                            "VER": 1,
                            "DEV": 1},
                        "lang": "es",
                        "theme": None,
                        "css": "https:\/\/www.u-cursos.cl\/d\/css\/style_externo_v7714.css",
                        "time": time.time(),
                        "mod_id": "eol",
                        "gru_id": "curso.372168",
                        "grupo": {
                                "base": "demo",
                                "anno": "2020",
                                "semestre": "0",
                                "codigo": "CV2020",
                                "seccion": "1",
                                "nombre": "Curso de prueba Virtual"}}))]

        result = self.client.get(
            reverse('edxucursos-login:login'),
            data={
                'ticket': 'testticket'})
        self.assertEquals(result.status_code, 404)
        self.assertEquals(result._container[0], 'User not Found')


class TestCallbackView(TestCase):
    def setUp(self):
        self.client = Client()
        self.token = str(uuid.uuid4())
        self.user = UserFactory(
            username='student',
            password='12345',
            email='student@edx.org')

    def test_normal(self):
        from uchileedxlogin.models import EdxLoginUser
        from rest_framework_jwt.settings import api_settings
        from datetime import datetime as dt
        import datetime
        payload = {'username': self.user.username,
                    'user_id': self.user.id,
                    'exp': dt.utcnow() + datetime.timedelta(seconds=settings.EDXCURSOS_EXP_TIME),
                    'course': 'demo/2020/0/CV2020/1'}
        
        if api_settings.JWT_AUDIENCE is not None:
            payload['aud'] = api_settings.JWT_AUDIENCE
        
        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
        token = jwt_encode_handler(payload)

        EdxLoginUser.objects.create(user=self.user, run='0000000108')
        EdxUCursosMapping.objects.create(edx_course='course-v1:mss+MSS001+2019_2',ucurso_course='demo/2020/0/CV2020/1')
        result = self.client.get(
            reverse('edxucursos-login:callback'),
            data={
                'token': token})
        self.assertEquals(result.status_code, 302)
        self.assertEquals(
            result._headers['location'], ('Location', '/courses/course-v1:mss+MSS001+2019_2/course/'))

    def test_callback_no_token(self):
        from uchileedxlogin.models import EdxLoginUser
        EdxLoginUser.objects.create(user=self.user, run='0000000108')
        result = self.client.get(
            reverse('edxucursos-login:callback'),
            data={
                'token': ""})
        self.assertEquals(result.status_code, 404)
        self.assertEquals(
            result._container[0],
            'Decoding failure')

    def test_callback_wrong_token_data(self):
        from uchileedxlogin.models import EdxLoginUser
        from rest_framework_jwt.settings import api_settings
        from datetime import datetime as dt
        import datetime
        payload = {'username': self.user.username,
                    'user_id': self.user.id,
                    'exp': dt.utcnow() + datetime.timedelta(seconds=settings.EDXCURSOS_EXP_TIME),
                    'course': 'demo/2020/0/CV2020/1'}
        payload['aud'] = "WRONG_AUD_TEST"
        
        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
        token = jwt_encode_handler(payload)

        EdxLoginUser.objects.create(user=self.user, run='0000000108')
        result = self.client.get(
            reverse('edxucursos-login:callback'),
            data={
                'token': token})
        self.assertEquals(result.status_code, 404)
        self.assertEquals(
            result._container[0],
            'Decoding failure')
    
    def test_callback_wrong_token(self):
        from uchileedxlogin.models import EdxLoginUser
        
        EdxLoginUser.objects.create(user=self.user, run='0000000108')
        result = self.client.get(
            reverse('edxucursos-login:callback'),
            data={
                'token': "asdfghjkl1234567890.123456789asdfghjk.asdfgh123456"})
        self.assertEquals(result.status_code, 404)
        self.assertEquals(
            result._container[0],
            'Decoding failure')

    def test_callback_expired_token(self):
        from uchileedxlogin.models import EdxLoginUser
        from rest_framework_jwt.settings import api_settings
        from datetime import datetime as dt
        import datetime
        payload = {'username': self.user.username,
                    'user_id': self.user.id,
                    'exp': dt.utcnow(),
                    'course': 'demo/2020/0/CV2020/1'}
        if api_settings.JWT_AUDIENCE is not None:
            payload['aud'] = api_settings.JWT_AUDIENCE
        
        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
        token = jwt_encode_handler(payload)
        import time
        time.sleep(2)
        EdxLoginUser.objects.create(user=self.user, run='0000000108')
        result = self.client.get(
            reverse('edxucursos-login:callback'),
            data={
                'token': token})
        self.assertEquals(result.status_code, 404)
        self.assertEquals(
            result._container[0],
            'Caducity Token')
    
    def test_callback_no_course(self):
        from uchileedxlogin.models import EdxLoginUser
        from rest_framework_jwt.settings import api_settings
        from datetime import datetime as dt
        import datetime
        payload = {'username': self.user.username,
                    'user_id': self.user.id,
                    'exp': dt.utcnow() + datetime.timedelta(seconds=settings.EDXCURSOS_EXP_TIME)}
        
        if api_settings.JWT_AUDIENCE is not None:
            payload['aud'] = api_settings.JWT_AUDIENCE
        
        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
        token = jwt_encode_handler(payload)

        EdxLoginUser.objects.create(user=self.user, run='0000000108')
        result = self.client.get(
            reverse('edxucursos-login:callback'),
            data={
                'token': token})
        self.assertEquals(result.status_code, 404)
        self.assertEquals(
            result._container[0],
            'Decoding failure: No Course')
    
    def test_callback_no_mapping_course(self):
        from uchileedxlogin.models import EdxLoginUser
        from rest_framework_jwt.settings import api_settings
        from datetime import datetime as dt
        import datetime
        payload = {'username': self.user.username,
                    'user_id': self.user.id,
                    'exp': dt.utcnow() + datetime.timedelta(seconds=settings.EDXCURSOS_EXP_TIME),
                    'course': 'test/2020/0/CV2020/1'}
        
        if api_settings.JWT_AUDIENCE is not None:
            payload['aud'] = api_settings.JWT_AUDIENCE
        
        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
        token = jwt_encode_handler(payload)

        EdxLoginUser.objects.create(user=self.user, run='0000000108')
        result = self.client.get(
            reverse('edxucursos-login:callback'),
            data={
                'token': token})
        self.assertEquals(result.status_code, 404)
        self.assertEquals(
            result._container[0],
            'EdxUCursosMapping DoesNotExist')