#!/usr/bin/env python
# -- coding: utf-8 --
# Python Standard Libraries
from datetime import datetime as dt
from itertools import cycle
from urllib.parse import urlencode
import datetime
import json
import logging
import time
import uuid

# Installed packages (via pip)
from django.conf import settings
from django.contrib.auth import login, logout
from django.contrib.auth.models import User
from django.db import transaction
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseNotFound
from django.urls import reverse
from django.views.generic.base import View
from rest_framework_jwt.settings import api_settings
from rest_framework_jwt.utils import jwt_get_secret_key
from uchileedxlogin.models import EdxLoginUser
from uchileedxlogin.views import EdxLoginStaff
import jwt
import requests
import six

# Internal project dependencies
from .models import EdxUCursosMapping

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
        if 'id_externo' in user_data:
            rut = user_data['id_externo']
        else:
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
        try:
            result = requests.get(
                settings.EDXUCURSOS_VERIFY_TICKET,
                params=urlencode(parameters),
                headers={
                    'content-type': 'application/json'})
            result.raise_for_status()
        except requests.exceptions.HTTPError:
            return {'result': 'error'}
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

    def digito_verificador(self, rut):
        """
            Return rut check digit
        """
        revertido = list(map(int, reversed(str(rut))))
        factors = cycle(list(range(2, 8)))
        s = sum(d * f for d, f in zip(revertido, factors))
        res = (-s) % 11

        if (str(res) == '10'):
            return 'K'
        
        return str(res)

    def get_edxucursos_mapping(self, data):
        """
            Return id_ucursos 
        """
        return '{}/{}/{}/{}/{}'.format(data['base'],
                                       data['anno'],
                                       data['semestre'],
                                       data['codigo'],
                                       data['seccion'])


    def get_payload(self, user, course):
        """
            Create payload with user data to create auth token
        """
        payload = {'username': user.username, 'user_id': user.id, 'exp': dt.utcnow(
        ) + datetime.timedelta(seconds=settings.EDXUCURSOS_EXP_TIME), 'course': course}

        if api_settings.JWT_AUDIENCE is not None:
            payload['aud'] = api_settings.JWT_AUDIENCE

        return payload

    def validate_data(self, rut, course):
        """
            Verify if rut and course are correct
        """
        try:
            if rut[0] == 'P':
                if 5 > len(rut[1:]) or len(rut[1:]) > 20:
                    logger.error("Rango de rut pasaporte debe ser mayor a 5 y menor a 20, {}".format(rut))
                    return False
            elif rut[0:2] == 'CG':
                if len(rut) != 10:
                    logger.error("Rango de rut CG debe ser 10, {}".format(rut))
                    return False
            else:
                if not EdxLoginStaff().validarRut(rut):
                    logger.error("Rut invalido en EdxLoginStaff().validarRut(rut): {}".format(rut))
                    return False
        except Exception:
            logger.error("Rut invalido: {}".format(rut))
            return False

        try:
            course = EdxUCursosMapping.objects.get(
                ucurso_course=course)
            course_id = six.text_type(course.edx_course)
        except EdxUCursosMapping.DoesNotExist:
            logger.error("No Existe EdxUCursosMapping, id: {}".format(course))
            return False

        # verify if exists course
        if not EdxLoginStaff().validate_course(course_id):
            logger.error("Curso no existe, id: {}".format(course_id))
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
        if "AYUDANTE" in data and data["AYUDANTE"] == 1:
            return "audit"
        return "honor"

    @staticmethod
    def get_callback_url(request, token):
        """
        Get the callback url
        """
        if settings.EDXUCURSOS_DOMAIN != "":
            url = '{}{}'.format(settings.EDXUCURSOS_DOMAIN, reverse('edxucursos-login:callback'))
        else:
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
