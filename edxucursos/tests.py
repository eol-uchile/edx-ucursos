#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Python Standard Libraries
from datetime import datetime as dt
from collections import namedtuple
import datetime
import json
import time
import uuid

# Installed packages (via pip)
from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase, Client
from django.test.utils import override_settings
from django.urls import reverse
from mock import patch, Mock
from requests.exceptions import HTTPError
from rest_framework_jwt.settings import api_settings
from uchileedxlogin.models import EdxLoginUser
from uchileedxlogin.views import EdxLoginStaff

# Edx dependencies
from common.djangoapps.student.tests.factories import UserFactory
from openedx.core.djangoapps.content.course_overviews.models import CourseOverview
from xmodule.modulestore.tests.django_utils import ModuleStoreTestCase
from xmodule.modulestore.tests.factories import CourseFactory

# Internal project dependencies
from .models import EdxUCursosMapping
from .views import EdxUCursosLoginRedirect

def create_user(user_data, have_pass):
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
        with patch('common.djangoapps.student.models.cc.User.save'):
            # staff user
            self.client = Client()
            self.user = UserFactory(
                username='testuser3',
                password='12345',
                email='student2@edx.org',
                is_staff=True)

    @patch('requests.get')
    def test_login_with_rut_dv_is_K(self, get):
        """
            Test EdxUCursosLoginRedirect normal procedure with rut_dv is K
        """
        EdxLoginUser.objects.create(user=self.user, run='019027537K')
        EdxUCursosMapping.objects.create(
            edx_course=self.course.id,
            ucurso_course='demo/2020/0/CV2020/1')
        get.side_effect = [
            namedtuple(
                "Request",
                [
                    "status_code",
                    "raise_for_status",
                    "text"])(
                200,
                Mock(),
                json.dumps(
                    {
                        "pers_id": 19027537,
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
                    "raise_for_status",
                    "text"])(
                200,
                Mock(),
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
    def test_login_server_error(self, get):
        """
            Testing when U-cursos ticket api is responding wrong
        """
        EdxLoginUser.objects.create(user=self.user, run='0000000108')
        get.side_effect = [
            namedtuple(
                "Request",
                [
                    "status_code",
                    "raise_for_status"])(
                404,
                Mock(side_effect=HTTPError('not found')))]

        result = self.client.get(
            reverse('edxucursos-login:login'),
            data={
                'ticket': 'testticket'})
        self.assertEqual(result.status_code, 404)
        self.assertTrue(
            'Error con la api de ucursos (ticket)' in
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
                    "raise_for_status",
                    "text"])(
                200,
                Mock(),
                'null')]

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
                    "raise_for_status",
                    "text"])(
                200,
                Mock(),
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
                    "raise_for_status",
                    "text"])(
                200,
                Mock(),
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
    @patch('requests.get')
    def test_login_create_user(self, get, mock_created_user):
        """
            Testing when edxlogin_user no exists
        """
        EdxUCursosMapping.objects.create(
            edx_course=self.course.id,
            ucurso_course='demo/2020/0/CV2020/1')

        get.side_effect = [namedtuple(
            "Request",
            [
                "status_code",
                "raise_for_status",
                "text"])(
            200,
            Mock(),
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
                        "json"])(200,
                                 lambda:{'data':{'getRowsPersona':{'status_code':200,'persona':[
                                            {"paterno": "TESTLASTNAME",
                                            "materno": "TESTLASTNAME",
                                            'pasaporte': [{'usuario':'avilio.perez'}],
                                            "nombres": "TEST NAME",
                                            'email': [{'email': 'student22@edx2.org'},{'email': 'student33@edx.org'},{'email': 'student44@edx.org'}],
                                            "indiv_id": "0000000108"}]}}})]

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
                'rut': '0000000108',
                'emails': ['student22@edx2.org','student33@edx.org', 'student44@edx.org'],
                'email': 'student22@edx2.org'})
        self.assertIn(
            'http://testserver/edxucursos/callback?token=',
            result._container[0].decode())

    @patch(
        "uchileedxlogin.views.EdxLoginStaff.create_user_by_data",
        side_effect=create_user)
    @patch('requests.get')
    def test_login_fail_create_user(self, get, mock_created_user):
        """
            Testing when fail in create user
        """
        EdxUCursosMapping.objects.create(
            edx_course=self.course.id,
            ucurso_course='demo/2020/0/CV2020/1')
        get.side_effect = [namedtuple(
            "Request",
            [
                "status_code",
                "raise_for_status",
                "text"])(
            200,
            Mock(),
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
                                 json.dumps({}))]
        result = self.client.get(
            reverse('edxucursos-login:login'),
            data={
                'ticket': 'testticket'})

        self.assertEqual(result.status_code, 404)
        self.assertTrue(
            'Error con los datos del usuario' in
            result._container[0].decode())

    @override_settings(EDXUCURSOS_DOMAIN="http://change.domain.com")
    @patch('requests.get')
    def test_login_with_domain(self, get):
        """
            Test EdxUCursosLoginRedirect normal procedure with domain settings
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
                    "raise_for_status",
                    "text"])(
                200,
                Mock(),
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
            'http://change.domain.com/edxucursos/callback?token=',
            result._container[0].decode())

    @patch('requests.get')
    def test_login_with_passport(self, get):
        """
            Test EdxUCursosLoginRedirect with passport
        """
        EdxLoginUser.objects.create(user=self.user, run='PABC112233')
        EdxUCursosMapping.objects.create(
            edx_course=self.course.id,
            ucurso_course='demo/2020/0/CV2020/1')
        get.side_effect = [
            namedtuple(
                "Request",
                [
                    "status_code",
                    "raise_for_status",
                    "text"])(
                200,
                Mock(),
                json.dumps(
                    {
                        "pers_id": 10,
                        "id_externo":"PABC112233",
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
    def test_login_with_wrong_passport(self, get):
        """
            Test EdxUCursosLoginRedirect with wrong passport
        """
        EdxLoginUser.objects.create(user=self.user, run='PABC1122')
        EdxUCursosMapping.objects.create(
            edx_course=self.course.id,
            ucurso_course='demo/2020/0/CV2020/1')
        get.side_effect = [
            namedtuple(
                "Request",
                [
                    "status_code",
                    "raise_for_status",
                    "text"])(
                200,
                Mock(),
                json.dumps(
                    {
                        "pers_id": 10,
                        "id_externo":"P112",
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

    @patch('requests.get')
    def test_login_with_CG_account(self, get):
        """
            Test EdxUCursosLoginRedirect with CG account
        """
        EdxLoginUser.objects.create(user=self.user, run='CG00112233')
        EdxUCursosMapping.objects.create(
            edx_course=self.course.id,
            ucurso_course='demo/2020/0/CV2020/1')
        get.side_effect = [
            namedtuple(
                "Request",
                [
                    "status_code",
                    "raise_for_status",
                    "text"])(
                200,
                Mock(),
                json.dumps(
                    {
                        "pers_id": 10,
                        "id_externo":"CG00112233",
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
    def test_login_with_CG_account_wrong(self, get):
        """
            Test EdxUCursosLoginRedirect with wrong CG account
        """
        EdxLoginUser.objects.create(user=self.user, run='CG00112233')
        EdxUCursosMapping.objects.create(
            edx_course=self.course.id,
            ucurso_course='demo/2020/0/CV2020/1')
        get.side_effect = [
            namedtuple(
                "Request",
                [
                    "status_code",
                    "raise_for_status",
                    "text"])(
                200,
                Mock(),
                json.dumps(
                    {
                        "pers_id": 10,
                        "id_externo":"CG001122",
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
        
    def test_validate_data_invalid_rut(self):
        """
        This test checks that the validate_data method correctly identifies an invalid format RUT and logs a warning. 
        It ensures the method enforces RUT validation rules and prevents further processing when the input is invalid.
        """
        with self.assertLogs('edxucursos.views', level='INFO') as cm:
            result = EdxUCursosLoginRedirect.validate_data(self, '111111', '123456789')
        self.assertFalse(result)
        self.assertTrue(any(
        'Rut invalido en EdxLoginStaff().validarRut(rut): 111111' in log
        for log in cm.output))

    def test_validate_data_none_as_rut(self):
        """
        This test checks that the validate_data method correctly identifies an invalid RUT in this case as a number instead of a string, and logs a warning.
        It ensures the method enforces RUT validation rules and prevents further processing when the input is invalid.
        """
        with self.assertLogs('edxucursos.views', level='INFO') as cm:
            result = EdxUCursosLoginRedirect.validate_data(self, 1111111, '123456789')
        self.assertFalse(result)
        self.assertTrue(any(
        'Rut invalido: 111111' in log
        for log in cm.output))
    
    def test_validate_data_course_invalid_data(self):
        """
        This test checks that the validate_data method correctly identifies an invalid course and logs a warning.
        """
        with self.assertLogs('edxucursos.views', level='INFO') as cm:
            result = EdxUCursosLoginRedirect.validate_data(self, '11111111-1', '123456789')
        self.assertFalse(result)
        self.assertTrue(any(
        'No Existe EdxUCursosMapping, id: 123456789' in log
        for log in cm.output))

    def test_get_mode_ayudante(self):
        """
        This test checks that when the input data includes "AYUDANTE": 1, the get_mode method returns "audit".
        """
        data = {
            "PROFESOR": 0,
            "AYUDANTE": 1
        }
        result = EdxUCursosLoginRedirect.get_mode(self, data)
        self.assertEqual(result, "audit")
    
    def test_get_mode_not_ayudante_or_profesor(self):
        """
        This test verifies that if the input data does not include "PROFESOR": 1 or "AYUDANTE": 1, the method returns "honor".
        """
        data = {
            "PROFESOR": 0,
            "AYUDANTE": 0
        }
        result = EdxUCursosLoginRedirect.get_mode(self, data)
        self.assertEqual(result, "honor")

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
                   'exp': dt.utcnow() + datetime.timedelta(seconds=settings.EDXUCURSOS_EXP_TIME),
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
                   'exp': dt.utcnow() + datetime.timedelta(seconds=settings.EDXUCURSOS_EXP_TIME),
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
        ) + datetime.timedelta(seconds=settings.EDXUCURSOS_EXP_TIME)}

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
                   'exp': dt.utcnow() + datetime.timedelta(seconds=settings.EDXUCURSOS_EXP_TIME),
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
                   'exp': dt.utcnow() + datetime.timedelta(seconds=settings.EDXUCURSOS_EXP_TIME),
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
                   'exp': dt.utcnow() + datetime.timedelta(seconds=settings.EDXUCURSOS_EXP_TIME),
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
    
    def test_callback_different_wrong_user_id(self):
        """
           Tests the behavior when a non-existent user_id is provided by verifying that the expected 
           log message is generated, indicating login error.
        """
        self.client.login(username='student', password='12345')
        payload = {'username': self.user.username,
                   'user_id': '11111111',
                   'exp': dt.utcnow() + datetime.timedelta(seconds=settings.EDXUCURSOS_EXP_TIME),
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
        
        self.assertEqual(result.status_code, 404)
        self.assertTrue(
            'Logging Error, reintente nuevamente' in
            result._container[0].decode())
