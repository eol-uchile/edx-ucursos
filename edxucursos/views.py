#!/usr/bin/env python
# -- coding: utf-8 --

from django.conf import settings
from django.core.exceptions import ValidationError
from django.contrib.auth import login, logout
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.db import transaction
from django.http import HttpResponseRedirect, HttpResponseForbidden, Http404, HttpResponseNotFound
from django.shortcuts import render
from django.urls import reverse
from django.views.generic.base import View
from django.http import HttpResponse
from uchileedxlogin.models import EdxLoginUser, EdxLoginUserCourseRegistration
from uchileedxlogin.views import EdxLoginStaff
from .models import EdxUCursosMapping
from urllib.parse import urlencode
from itertools import cycle
from opaque_keys.edx.keys import CourseKey
from opaque_keys import InvalidKeyError
from courseware.courses import get_course_by_id, get_course_with_access
from courseware.access import has_access
from util.json_request import JsonResponse, JsonResponseBadRequest
from rest_framework_jwt.settings import api_settings
from datetime import datetime as dt
from rest_framework_jwt.utils import jwt_get_secret_key
import datetime
import json
import requests
import uuid
import unidecode
import logging
import sys
import unicodecsv as csv
import time
import jwt
import six

logger = logging.getLogger(__name__)
msg_error = "contáctese al correo eol-ayuda@uchile.cl adjuntando el número del error"

class EdxUCursosLoginRedirect(View):
    """
        Return a url with user token to log in
    """
    def get(self, request):
        ticket = request.GET.get('ticket', "")
        logger.info('ticket: ' + ticket)
        user_data = self.get_data_ticket(ticket)
        if user_data['result'] == 'error':
            id_error = str(uuid.uuid4())
            logger.error(id_error + '- Data error')
            logger.info(user_data)
            return HttpResponseNotFound(
                '(Error '+ id_error +') Error con la api de ucursos (ticket), por favor '+ msg_error)

        if self.verify_caducity(user_data):
            id_error = str(uuid.uuid4())
            logger.error(id_error + ' - Ticket caducado: ' + ticket)
            return HttpResponseNotFound(
                '(Error '+ id_error +') Ticket caducado, reintente nuevamente o '+ msg_error)

        rut = str(user_data['pers_id'])
        rut_dv = self.digito_verificador(rut)
        while len(rut) < 9:
            rut = "0" + rut
        rut = rut + rut_dv

        u_course = self.get_edxucursos_mapping(user_data['grupo'])
        mapp_course = self.validate_data(rut, u_course)
        if not mapp_course:
            id_error = str(uuid.uuid4())
            logger.error(id_error + '- Error con los parametros: rut de usuario o id del curso')
            return HttpResponseNotFound(
                '(Error '+ id_error +') Error con los parametros: rut de usuario o id del curso, por favor '+ msg_error)

        mode = self.get_mode(user_data["permisos"])
        edxlogin_user = self.enroll_or_create_user(rut, mapp_course, mode)

        if edxlogin_user:
            jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

            payload = self.get_payload(edxlogin_user.user, u_course)
            token = jwt_encode_handler(payload)
            return HttpResponse(
                EdxUCursosLoginRedirect.get_callback_url(request, token))
        else:
            id_error = str(uuid.uuid4())
            logger.error(id_error + ' - Error creating user')
            return HttpResponseNotFound(
                '(Error '+ id_error +') Error con los datos del usuario, por favor '+ msg_error)

    def get_data_ticket(self, ticket):
        """
            Get user data through the ticket
        """
        parameters = {
            'ticket': ticket
        }
        result = requests.get(
            settings.EDXUCURSOS_VERIFY_TICKET,
            params=urlencode(parameters),
            headers={
                'content-type': 'application/json'})
        logger.info(result.text)
        if result.text != 'null':
            data = json.loads(result.text)
            data['result'] = 'success'
            return data
        return {'result': 'error'}

    def verify_caducity(self, data):
        """
            Check if ticket is expired
        """
        aux_time = time.time()
        if (aux_time - data["time"]) > 60:
            return True
        return False

    def digito_verificador(self, run):
        """
            Return rut check digit
        """
        rut = reversed(list(map(int, run)))
        m = [2, 3, 4, 5, 6, 7]

        d = sum([n * m[i % 6] for i, n in enumerate(rut)])
        d %= 11

        if (d == 1):
            d = 'K'
        else:
            d = 11 - d
        return str(d)

    def get_edxucursos_mapping(self, data):
        """
            Return id_ucursos 
        """
        return '{}/{}/{}/{}/{}'.format(data['base'],
                                       data['anno'],
                                       data['semestre'],
                                       data['codigo'],
                                       data['seccion'])

    def login_user(self, request, edxlogin_user):
        """
            Login user
        """
        login(
            request,
            edxlogin_user.user,
            backend="django.contrib.auth.backends.AllowAllUsersModelBackend",
        )
        return token

    def get_payload(self, user, course):
        """
            Create payload with user data to create auth token
        """
        payload = {'username': user.username, 'user_id': user.id, 'exp': dt.utcnow(
        ) + datetime.timedelta(seconds=settings.EDXCURSOS_EXP_TIME), 'course': course}

        if api_settings.JWT_AUDIENCE is not None:
            payload['aud'] = api_settings.JWT_AUDIENCE

        return payload

    def validate_data(self, rut, course):
        """
            Verify if rut and course are correct
        """
        try:
            if not EdxLoginStaff().validarRut(rut):
                return False
        except Exception:
            return False

        try:
            course = EdxUCursosMapping.objects.get(
                ucurso_course=course)
            course_id = six.text_type(course.edx_course)
        except EdxUCursosMapping.DoesNotExist:
            return False

        # verify if exists course
        if not EdxLoginStaff().validate_course(course_id):
            return False

        return course

    def enroll_or_create_user(self, run, course, mode):
        """
            Get o create edxlogin_user and enroll to course
        """
        with transaction.atomic():
            try:
                edxlogin_user = EdxLoginUser.objects.get(run=run)
                EdxLoginStaff().enroll_course(
                    edxlogin_user, six.text_type(
                        course.edx_course), True, mode)
                logger.info(
                    'Exists EdxLogin_User: ' +
                    edxlogin_user.user.username)
                return edxlogin_user
            except EdxLoginUser.DoesNotExist:
                logger.info('Force Create User')
                edxlogin_user = EdxLoginStaff().force_create_user(run)
                if edxlogin_user:
                    EdxLoginStaff().enroll_course(
                        edxlogin_user, six.text_type(
                            course.edx_course), True, mode)
                    return edxlogin_user
        return None

    def get_mode(self, data):
        """
            Return mode data.
            audit == Profesor
            honor == Estudiante
        """
        if "PROFESOR" in data and data["PROFESOR"] == 1:
            return "audit"
        return "honor"

    @staticmethod
    def get_callback_url(request, token):
        """
        Get the callback url
        """
        url = request.build_absolute_uri(reverse('edxucursos-login:callback'))
        return '{}?token={}'.format(url, token)


class EdxUCursosCallback(View):
    """
        Login user if token is valid
    """
    def get(self, request):
        token = request.GET.get('token', "")
        logger.info('token: ' + token)

        #decode token
        try:
            payload = self.decode_token(token)
        except jwt.ExpiredSignatureError:
            id_error = str(uuid.uuid4())
            logger.error(id_error +' - Caducity Ticket')
            return HttpResponseNotFound(
                '(Error '+ id_error +') Ticket caducado, reintente nuevamente o '+ msg_error)
        except Exception:
            id_error = str(uuid.uuid4())
            logger.error(id_error + ' - Decoding failure')
            return HttpResponseNotFound(
                '(Error '+ id_error +') Error en la decoficación, reintente nuevamente o '+ msg_error)
        #verify if course parameter exists
        if 'course' not in payload:
            id_error = str(uuid.uuid4())
            logger.error(id_error + ' - Decoding failure: No Course')
            return HttpResponseNotFound(
                '(Error '+ id_error +') Error en la decoficación (parametro: curso), reintente nuevamente o '+ msg_error)
        #verify course_id exists
        try:
            course = EdxUCursosMapping.objects.get(
                ucurso_course=payload['course'])
            course_id = six.text_type(course.edx_course)
        except EdxUCursosMapping.DoesNotExist:
            id_error = str(uuid.uuid4())
            logger.error(id_error + ' - El curso no se ha vinculado con un curso de eol')
            return HttpResponseNotFound(
                '(Error '+ id_error +') El curso no se ha vinculado con un curso de eol, por favor '+ msg_error)

        try:
            login_user = User.objects.get(id=payload['user_id'])
            if request.user.is_anonymous or request.user.id != login_user.id:
                logout(request)
                login(
                    request,
                    login_user,
                    backend="django.contrib.auth.backends.AllowAllUsersModelBackend",
                )
            request.session.set_expiry(0)
            return HttpResponseRedirect(
                "/courses/{}/course/".format(course_id))
        except (User.DoesNotExist, Exception):
            id_error = str(uuid.uuid4())
            logger.error(id_error + ' - Logging Error')
            return HttpResponseNotFound(
                '(Error '+ id_error +') Logging Error, reintente nuevamente o '+ msg_error)

    def decode_token(self, token):
        """
            Decode token
        """
        options = {
            'verify_exp': True,
            'verify_aud': True
        }
        unverified_payload = jwt.decode(token, None, False)
        secret_key = jwt_get_secret_key(unverified_payload)
        return jwt.decode(
            token,
            api_settings.JWT_PUBLIC_KEY or secret_key,
            api_settings.JWT_VERIFY,
            options=options,
            leeway=api_settings.JWT_LEEWAY,
            audience=api_settings.JWT_AUDIENCE,
            algorithms=[api_settings.JWT_ALGORITHM]
        )
