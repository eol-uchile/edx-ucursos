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
from urllib.parse import parse_qs
from opaque_keys.edx.locator import CourseLocator
from student.tests.factories import CourseEnrollmentAllowedFactory, UserFactory, CourseEnrollmentFactory
from xmodule.modulestore.tests.factories import CourseFactory, ItemFactory
from xmodule.modulestore import ModuleStoreEnum
from xmodule.modulestore.tests.django_utils import ModuleStoreTestCase
from openedx.core.djangoapps.content.course_overviews.models import CourseOverview
from student.roles import CourseInstructorRole, CourseStaffRole
from .views import EdxUCursosLoginRedirect, EdxUCursosCallback
from .models import EdxUCursosMapping
from uchileedxlogin.models import EdxLoginUser
from uchileedxlogin.views import EdxLoginStaff
from rest_framework_jwt.settings import api_settings
from datetime import datetime as dt
import datetime
import time
import re
import json
import urllib.parse
import time
import uuid


def create_user(user_data):
    return User.objects.create_user(
        username=EdxLoginStaff().generate_username(user_data),
        email=user_data['email'])


class TestRedirectView(ModuleStoreTestCase):
    def setUp(self):
        super(TestRedirectView, self).setUp()
        self.course = CourseFactory.create(
            org='mss',
            course='999',
            display_name='2020',
            emit_signals=True)
        aux = CourseOverview.get_from_id(self.course.id)
        with patch('student.models.cc.User.save'):
            # staff user
            self.client = Client()
            self.user = UserFactory(
                username='testuser3',
                password='12345',
                email='student2@edx.org',
                is_staff=True)

    @patch('requests.get')
    def test_login(self, get):
        """
            Test EdxUCursosLoginRedirect normal procedure
        """
        EdxLoginUser.objects.create(user=self.user, run='0000000108')
        EdxUCursosMapping.objects.create(
            edx_course=self.course.id,
            ucurso_course='demo/2020/0/CV2020/1')
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
            result._container[0].decode())

    @patch('requests.get')
    def test_login_wrong_or_none_ticket(self, get):
        """
            Testing when ticket is wrong or none
        """
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
        self.assertEqual(result.status_code, 404)
        self.assertTrue(
            'Error con la api de ucursos (ticket)' in
            result._container[0].decode())

    @patch('requests.get')
    def test_login_caducity_ticket(self, get):
        """
            Testing when ticket is expired
        """
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
        self.assertEqual(result.status_code, 404)
        self.assertTrue(
            'Ticket caducado, reintente nuevamente' in
            result._container[0].decode())

    @patch('requests.get')
    def test_login_no_exists_course(self, get):
        """
            Testing when course no exists
        """
        EdxLoginUser.objects.create(user=self.user, run='0000000108')
        EdxUCursosMapping.objects.create(
            edx_course='course-v1:mss+MSS001+2019_2',
            ucurso_course='demo/2020/0/CV2020/1')
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

        self.assertEqual(result.status_code, 404)
        self.assertTrue(
            'Error con los parametros' in
            result._container[0].decode())

    @patch(
        "uchileedxlogin.views.EdxLoginStaff.create_user_by_data",
        side_effect=create_user)
    @patch('requests.post')
    @patch('requests.get')
    def test_login_create_user(self, get, post, mock_created_user):
        """
            Testing when edxlogin_user no exists
        """
        EdxUCursosMapping.objects.create(
            edx_course=self.course.id,
            ucurso_course='demo/2020/0/CV2020/1')
        data = {"cuentascorp": [{"cuentaCorp": "avilio.perez@ug.uchile.cl",
                                 "tipoCuenta": "EMAIL",
                                 "organismoDominio": "ug.uchile.cl"},
                                {"cuentaCorp": "avilio.perez@uchile.cl",
                                 "tipoCuenta": "EMAIL",
                                 "organismoDominio": "uchile.cl"},
                                {"cuentaCorp": "avilio.perez@u.uchile.cl",
                                 "tipoCuenta": "EMAIL",
                                 "organismoDominio": "u.uchile.cl"},
                                {"cuentaCorp": "avilio.perez",
                                 "tipoCuenta": "CUENTA PASAPORTE",
                                 "organismoDominio": "Universidad de Chile"}]}

        get.side_effect = [namedtuple(
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
                        "nombre": "Curso de prueba Virtual"}})),
            namedtuple("Request",
                       ["status_code",
                        "text"])(200,
                                 json.dumps({"apellidoPaterno": "TESTLASTNAME",
                                             "apellidoMaterno": "TESTLASTNAME",
                                             "nombres": "TEST NAME",
                                             "nombreCompleto": "TEST NAME TESTLASTNAME TESTLASTNAME",
                                             "rut": "0000000108"}))]
        post.side_effect = [namedtuple("Request",
                                       ["status_code",
                                        "text"])(200,
                                                 json.dumps(data)),
                            namedtuple("Request",
                                       ["status_code",
                                        "text"])(200,
                                                 json.dumps({"emails": [{"rut": "0000000108",
                                                                         "email": "test@test.test",
                                                                         "codigoTipoEmail": "1",
                                                                         "nombreTipoEmail": "PRINCIPAL"}]}))]
        result = self.client.get(
            reverse('edxucursos-login:login'),
            data={
                'ticket': 'testticket'})

        self.assertEqual(result.status_code, 200)
        self.assertEqual(
            mock_created_user.call_args_list[0][0][0],
            {
                'username': 'avilio.perez',
                'apellidoMaterno': 'TESTLASTNAME',
                'nombres': 'TEST NAME',
                'apellidoPaterno': 'TESTLASTNAME',
                'nombreCompleto': 'TEST NAME TESTLASTNAME TESTLASTNAME',
                'rut': '0000000108',
                'email': 'test@test.test'})
        self.assertIn(
            'http://testserver/edxucursos/callback?token=',
            result._container[0].decode())

    @patch(
        "uchileedxlogin.views.EdxLoginStaff.create_user_by_data",
        side_effect=create_user)
    @patch('requests.post')
    @patch('requests.get')
    def test_login_fail_create_user(self, get, post, mock_created_user):
        """
            Testing when fail in create user
        """
        EdxUCursosMapping.objects.create(
            edx_course=self.course.id,
            ucurso_course='demo/2020/0/CV2020/1')
        data = {"cuentascorp": [{"cuentaCorp": "avilio.perez@ug.uchile.cl",
                                 "tipoCuenta": "EMAIL",
                                 "organismoDominio": "ug.uchile.cl"},
                                {"cuentaCorp": "avilio.perez@uchile.cl",
                                 "tipoCuenta": "EMAIL",
                                 "organismoDominio": "uchile.cl"},
                                {"cuentaCorp": "avilio.perez@u.uchile.cl",
                                 "tipoCuenta": "EMAIL",
                                 "organismoDominio": "u.uchile.cl"},
                                {"cuentaCorp": "avilio.perez",
                                 "tipoCuenta": "CUENTA PASAPORTE",
                                 "organismoDominio": "Universidad de Chile"}]}

        get.side_effect = [namedtuple(
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
                        "nombre": "Curso de prueba Virtual"}})),
            namedtuple("Request",
                       ["status_code",
                        "text"])(404,
                                 json.dumps({"apellidoPaterno": "TESTLASTNAME",
                                             "apellidoMaterno": "TESTLASTNAME",
                                             "nombres": "TEST NAME",
                                             "nombreCompleto": "TEST NAME TESTLASTNAME TESTLASTNAME",
                                             "rut": "0000000108"}))]
        post.side_effect = [namedtuple("Request",
                                       ["status_code",
                                        "text"])(200,
                                                 json.dumps(data)),
                            namedtuple("Request",
                                       ["status_code",
                                        "text"])(200,
                                                 json.dumps({"emails": [{"rut": "0000000108",
                                                                         "email": "test@test.test",
                                                                         "codigoTipoEmail": "1",
                                                                         "nombreTipoEmail": "PRINCIPAL"}]}))]
        result = self.client.get(
            reverse('edxucursos-login:login'),
            data={
                'ticket': 'testticket'})

        self.assertEqual(result.status_code, 404)
        self.assertTrue(
            'Error con los datos del usuario' in
            result._container[0].decode())


class TestCallbackView(TestCase):
    def setUp(self):
        self.client = Client()
        self.token = str(uuid.uuid4())
        self.user = UserFactory(
            username='testuser',
            password='12345',
            email='testuser@edx.org')
        self.student = UserFactory(
            username='student',
            password='12345',
            email='student@edx.org')

    def test_normal(self):
        """
            Test EdxUCursosCallback normal procedure
        """
        payload = {'username': self.user.username,
                   'user_id': self.user.id,
                   'exp': dt.utcnow() + datetime.timedelta(seconds=settings.EDXCURSOS_EXP_TIME),
                   'course': 'demo/2020/0/CV2020/1'}

        if api_settings.JWT_AUDIENCE is not None:
            payload['aud'] = api_settings.JWT_AUDIENCE

        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
        token = jwt_encode_handler(payload)

        EdxLoginUser.objects.create(user=self.user, run='0000000108')
        EdxUCursosMapping.objects.create(
            edx_course='course-v1:mss+MSS001+2019_2',
            ucurso_course='demo/2020/0/CV2020/1')
        result = self.client.get(
            reverse('edxucursos-login:callback'),
            data={
                'token': token})
        self.assertEqual(result.status_code, 302)
        self.assertEqual(
            result._headers['location'],
            ('Location',
             '/courses/course-v1:mss+MSS001+2019_2/course/'))

    def test_callback_no_token(self):
        """
            Testing when token is empty
        """
        result = self.client.get(
            reverse('edxucursos-login:callback'),
            data={
                'token': ""})
        self.assertEqual(result.status_code, 404)
        self.assertTrue(
            'Error en la decoficación' in
            result._container[0].decode())

    def test_callback_wrong_token_data(self):
        """
            Testing when data token is wrong
        """
        payload = {'username': self.user.username,
                   'user_id': self.user.id,
                   'exp': dt.utcnow() + datetime.timedelta(seconds=settings.EDXCURSOS_EXP_TIME),
                   'course': 'demo/2020/0/CV2020/1'}
        payload['aud'] = "WRONG_AUD_TEST"

        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
        token = jwt_encode_handler(payload)
        result = self.client.get(
            reverse('edxucursos-login:callback'),
            data={
                'token': token})
        self.assertEqual(result.status_code, 404)
        self.assertTrue(
            'Error en la decoficación' in
            result._container[0].decode())

    def test_callback_wrong_token(self):
        """
            Testing when token is wrong
        """
        result = self.client.get(
            reverse('edxucursos-login:callback'),
            data={
                'token': "asdfghjkl1234567890.123456789asdfghjk.asdfgh123456"})
        self.assertEqual(result.status_code, 404)
        self.assertTrue(
            'Error en la decoficación' in
            result._container[0].decode())

    def test_callback_expired_token(self):
        """
            Testing when token is expired
        """
        payload = {'username': self.user.username,
                   'user_id': self.user.id,
                   'exp': dt.utcnow(),
                   'course': 'demo/2020/0/CV2020/1'}
        if api_settings.JWT_AUDIENCE is not None:
            payload['aud'] = api_settings.JWT_AUDIENCE

        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
        token = jwt_encode_handler(payload)
        time.sleep(2)
        result = self.client.get(
            reverse('edxucursos-login:callback'),
            data={
                'token': token})
        self.assertEqual(result.status_code, 404)
        self.assertTrue(
            'Ticket caducado' in
            result._container[0].decode())

    def test_callback_no_course(self):
        """
            Testing when course data no exists
        """
        payload = {'username': self.user.username, 'user_id': self.user.id, 'exp': dt.utcnow(
        ) + datetime.timedelta(seconds=settings.EDXCURSOS_EXP_TIME)}

        if api_settings.JWT_AUDIENCE is not None:
            payload['aud'] = api_settings.JWT_AUDIENCE

        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
        token = jwt_encode_handler(payload)
        result = self.client.get(
            reverse('edxucursos-login:callback'),
            data={
                'token': token})
        self.assertEqual(result.status_code, 404)
        self.assertTrue(
            'Error en la decoficación (parametro: curso)' in
            result._container[0].decode())

    def test_callback_no_mapping_course(self):
        """
            Testing when ucurse_id no exists
        """
        payload = {'username': self.user.username,
                   'user_id': self.user.id,
                   'exp': dt.utcnow() + datetime.timedelta(seconds=settings.EDXCURSOS_EXP_TIME),
                   'course': 'test/2020/0/CV2020/1'}

        if api_settings.JWT_AUDIENCE is not None:
            payload['aud'] = api_settings.JWT_AUDIENCE

        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
        token = jwt_encode_handler(payload)
        result = self.client.get(
            reverse('edxucursos-login:callback'),
            data={
                'token': token})
        self.assertEqual(result.status_code, 404)
        self.assertTrue(
            'El curso no se ha vinculado con un curso de eol' in
            result._container[0].decode())

    def test_callback_user_logged(self):
        """
            Test when user is already logged
        """
        self.client.login(username='student', password='12345')
        payload = {'username': self.user.username,
                   'user_id': self.student.id,
                   'exp': dt.utcnow() + datetime.timedelta(seconds=settings.EDXCURSOS_EXP_TIME),
                   'course': 'demo/2020/0/CV2020/1'}

        if api_settings.JWT_AUDIENCE is not None:
            payload['aud'] = api_settings.JWT_AUDIENCE

        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
        token = jwt_encode_handler(payload)
        EdxUCursosMapping.objects.create(
            edx_course='course-v1:mss+MSS001+2019_2',
            ucurso_course='demo/2020/0/CV2020/1')
        result = self.client.get(
            reverse('edxucursos-login:callback'),
            data={
                'token': token})
        self.assertEqual(result.status_code, 302)
        self.assertEqual(
            result._headers['location'],
            ('Location',
             '/courses/course-v1:mss+MSS001+2019_2/course/'))

    def test_callback_different_user_logged(self):
        """
            Test when another user is already logged
        """
        self.client.login(username='student', password='12345')
        payload = {'username': self.user.username,
                   'user_id': self.user.id,
                   'exp': dt.utcnow() + datetime.timedelta(seconds=settings.EDXCURSOS_EXP_TIME),
                   'course': 'demo/2020/0/CV2020/1'}

        if api_settings.JWT_AUDIENCE is not None:
            payload['aud'] = api_settings.JWT_AUDIENCE

        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
        token = jwt_encode_handler(payload)

        EdxUCursosMapping.objects.create(
            edx_course='course-v1:mss+MSS001+2019_2',
            ucurso_course='demo/2020/0/CV2020/1')
        result = self.client.get(
            reverse('edxucursos-login:callback'),
            data={
                'token': token})
        
        self.assertEqual(result.status_code, 302)
        self.assertEqual(
            result._headers['location'],
            ('Location',
             '/courses/course-v1:mss+MSS001+2019_2/course/'))