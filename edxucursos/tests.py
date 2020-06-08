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

from .views import EdxUCursosLoginRedirect


class TestRedirectView(TestCase):

    def setUp(self):
        self.client_login = Client()
        self.client = Client()
        self.user = UserFactory(
            username='student',
            password='12345',
            email='student@edx.org')

    def test_redirect_already_logged(self):
        user = User.objects.create_user(username='testuser', password='123')
        self.client_login.login(username='testuser', password='123')
        result = self.client_login.get(reverse('edxucursos-login:login'))
        assert_true(
            'http://testserver/?token=None' not in result._container[0])
        self.assertIn('http://testserver/?token=', result._container[0])

    @patch('requests.get')
    def test_login(self, get):
        from uchileedxlogin.models import EdxLoginUser
        EdxLoginUser.objects.create(user=self.user, run='019027537K')
        get.side_effect = [
            namedtuple(
                "Request",
                [
                    "status_code",
                    "text"])(
                200,
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
        assert_true(
            'http://testserver/?token=None' not in result._container[0])
        self.assertIn('http://testserver/?token=', result._container[0])

    @patch('requests.get')
    def test_login_wrong_or_none_ticket(self, get):
        from uchileedxlogin.models import EdxLoginUser
        EdxLoginUser.objects.create(user=self.user, run='019027537K')
        get.side_effect = [
            namedtuple(
                "Request",
                [
                    "status_code",
                    "text"])(
                404,
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
                'ticket': 'wrongticket'})
        self.assertEquals(result.status_code, 404)
        self.assertEquals(
            result._container[0],
            'Error with ucursos api - ticket')

    @patch('requests.get')
    def test_login_caducity_ticket(self, get):
        from uchileedxlogin.models import EdxLoginUser
        EdxLoginUser.objects.create(user=self.user, run='019027537K')
        get.side_effect = [
            namedtuple(
                "Request",
                [
                    "status_code",
                    "text"])(
                200,
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
        self.assertEquals(result.status_code, 404)
        self.assertEquals(result._container[0], 'User not Found')
