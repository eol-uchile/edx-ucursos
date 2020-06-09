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
from .models import EdxUCursosTokens
import re
import json
import urlparse
import time
import uuid
from .views import EdxUCursosLoginRedirect, EdxUCursosCallback


class TestRedirectView(TestCase):

    def setUp(self):
        self.client_login = Client()
        self.client = Client()
        self.token = str(uuid.uuid4())
        self.user = UserFactory(
            username='student',
            password='12345',
            email='student@edx.org')

    @patch('requests.get')
    def test_redirect_already_logged(self, get):
        from uchileedxlogin.models import EdxLoginUser
        user = User.objects.create_user(username='testuser', password='123')
        EdxLoginUser.objects.create(user=user, run='0000000108')
        EdxUCursosTokens.objects.create(token=self.token, user=user)
        self.client_login.login(username='testuser', password='123')
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

        result = self.client_login.get(reverse('edxucursos-login:login'))
        edxucursostoken = EdxUCursosTokens.objects.get(user=user)
        self.assertNotEqual(edxucursostoken.token, self.token)
        self.assertEquals(
            'http://testserver/edxucursos/callback?token=' +
            edxucursostoken.token,
            result._container[0])

    @patch('requests.get')
    def test_redirect_already_logged_no_token(self, get):
        from uchileedxlogin.models import EdxLoginUser

        user = User.objects.create_user(username='testuser2', password='123')
        EdxLoginUser.objects.create(user=user, run='0000000108')
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

        self.client_login.login(username='testuser2', password='123')
        result = self.client_login.get(reverse('edxucursos-login:login'))
        edxucursostoken = EdxUCursosTokens.objects.get(user=user)
        self.assertEquals(
            'http://testserver/edxucursos/callback?token=' +
            edxucursostoken.token,
            result._container[0])

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

        edxucursostoken = EdxUCursosTokens.objects.get(user=self.user)
        self.assertEquals(
            'http://testserver/edxucursos/callback?token=' +
            edxucursostoken.token,
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
        EdxLoginUser.objects.create(user=self.user, run='0000000108')
        EdxUCursosTokens.objects.create(token=self.token, user=self.user)
        result = self.client.get(
            reverse('edxucursos-login:callback'),
            data={
                'token': self.token})
        self.assertEquals(result.status_code, 302)
        self.assertEquals(
            result._headers['location'], ('Location', '/dashboard'))

    def test_callback_wrong_or_no_token(self):
        from uchileedxlogin.models import EdxLoginUser
        EdxLoginUser.objects.create(user=self.user, run='0000000108')
        EdxUCursosTokens.objects.create(token=self.token, user=self.user)
        result = self.client.get(
            reverse('edxucursos-login:callback'),
            data={
                'token': ""})
        self.assertEquals(result.status_code, 404)
        self.assertEquals(
            result._container[0],
            'Logging Error: Token no Exists')
