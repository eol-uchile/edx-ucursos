#!/usr/bin/env python
# -- coding: utf-8 --
# Python Standard Libraries
from itertools import cycle
from urllib.parse import urlencode
import base64
import json
import logging
import time
import uuid

# Installed packages (via pip)
from django.conf import settings
from django.http import HttpResponse, HttpResponseNotFound
from django.urls import reverse
from django.utils.http import urlquote_plus
from django.views.generic.base import TemplateView, View
from eol_sso.services.interface import sso_user_factory, EmailException, get_user_by_indiv_id, PhApiException
import requests
import six

# Edx dependencies
from common.djangoapps.student.models import CourseEnrollment
from opaque_keys import InvalidKeyError
from opaque_keys.edx.keys import CourseKey
from openedx.core.djangoapps.content.course_overviews.models import CourseOverview

# Internal project dependencies
from .models import EdxUCursosMapping

logger = logging.getLogger(__name__)
MSG_ERROR = "contáctese al correo eol-ayuda@uchile.cl adjuntando el número del error"

class EdxUCursosLoginRedirect(View):
    """
    Return a url with user token to log in.
    """
    def get(self, request):
        error_id = str(uuid.uuid4())
        ticket = request.GET.get('ticket', "")
        logger.info('ticket: ' + ticket)
        user_data = self.get_data_ticket(ticket)
        if user_data['result'] == 'error':
            logger.error(error_id + '- Data error')
            logger.info(user_data)
            return HttpResponseNotFound(
                '(Error '+ error_id +') Error con la api de ucursos (ticket), por favor '+ MSG_ERROR)

        if self.verify_caducity(user_data):
            logger.error(error_id + ' - Ticket caducado: ' + ticket)
            return HttpResponseNotFound(
                '(Error '+ error_id +') Ticket caducado, reintente nuevamente o '+ MSG_ERROR)
        if 'id_externo' in user_data:
            doc_id = user_data['id_externo']
        # If the user doesn't have an id_externo it is assumed that its pers_id is a rut without the verification digit.
        else:
            # Rut formatting.
            doc_id = str(user_data['pers_id'])
            ver_digit = self.verification_digit(doc_id)
            while len(doc_id) < 9:
                doc_id = "0" + doc_id
            doc_id = doc_id + ver_digit
        u_course = self.get_edxucursos_mapping(user_data['grupo'])
        mapp_course = self.validate_data(u_course)
        if not mapp_course:
            logger.error(error_id + '- Error con el parametro: id del curso')
            return HttpResponseNotFound(
                '(Error '+ error_id +') Error con el parametro: id del curso, por favor '+ MSG_ERROR)
        mode = self.get_mode(user_data["permisos"])
        user = get_user_by_indiv_id(doc_id)
        if not user:
            try:
               sso_user = sso_user_factory(doc_id, "doc_id")
               user = sso_user.user
            except ValueError:
                logger.error(f'{error_id} - Error when trying to create edxloginuser with doc_id: {doc_id}')
                return HttpResponseNotFound(
                    f'(Error {error_id}) Error con la validacion del doc_id del usuario, por favor {MSG_ERROR}')
            except PhApiException:
                logger.error(f'{error_id} - Error when trying to create edxloginuser with doc_id: {doc_id}')
                return HttpResponseNotFound(
                    f'(Error {error_id}) Error con la obtencion de datos desde ph para el usuario, por favor {MSG_ERROR}')
            except EmailException:
                logger.error(f'{error_id} - Error when trying to create edxloginuser with doc_id: {doc_id}')
                return HttpResponseNotFound(
                    f'(Error {error_id}) Error con los correos del usuario, por favor {MSG_ERROR}')
            except Exception:
                logger.error(f'{error_id} - Error when trying to create edxloginuser with doc_id: {doc_id}')
                return HttpResponseNotFound(
                    f'(Error {error_id}) Error con los datos del usuario, por favor {MSG_ERROR}')
        # Enroll the user.
        CourseEnrollment.enroll(user, CourseKey.from_string(str(mapp_course.edx_course)), mode=mode)
        # Generate the SSO login URL and return it in the response body
        target_path = "/courses/{}/course/".format(str(mapp_course.edx_course))
        url = request.build_absolute_uri(
            reverse('edxucursos-login:launch'))
        return HttpResponse(
            '{}?next={}'.format(url, urlquote_plus(target_path)))

    def get_data_ticket(self, ticket):
        """
        Get user data through the ticket.
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
        Check if the ticket is expired.
        """
        aux_time = time.time()
        if (aux_time - data["time"]) > 60:
            return True
        return False

    def verification_digit(self, rut):
        """
        Calculate the verification digit of a rut.
        """
        revertido = list(map(int, reversed(str(rut))))
        factors = cycle(list(range(2, 8)))
        s = sum(d * f for d, f in zip(revertido, factors))
        res = (-s) % 11

        if (str(res) == '10'):
            return 'K'
        
        return str(res)
    
    def validate_course(self, course_id):
        """
        Verify if a course associated with course_id exists.
        """
        try:
            course_key = CourseKey.from_string(course_id)
            return CourseOverview.objects.filter(id=course_key).exists()
        except InvalidKeyError:
            return False

    def get_edxucursos_mapping(self, data):
        """
        Return id_ucursos.
        """
        return '{}/{}/{}/{}/{}'.format(data['base'],
                                       data['anno'],
                                       data['semestre'],
                                       data['codigo'],
                                       data['seccion'])

    def validate_data(self, course):
        """
        Verify if the course exists and if its associated to a Ucursos course.
        """
        # Checks if there is a mapping between course and a ucursos course.
        try:
            course = EdxUCursosMapping.objects.get(
                ucurso_course=course)
            course_id = six.text_type(course.edx_course)
        except EdxUCursosMapping.DoesNotExist:
            logger.error("No Existe EdxUCursosMapping, id: {}".format(course))
            return False
        # Checks if the course exists.
        if not self.validate_course(course_id):
            logger.error("Curso no existe, id: {}".format(course_id))
            return False
        return course

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

class EdxUcursosLoginLaunch(TemplateView):
    template_name = 'edxucursos/redirect.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Create the redirect url using the next parameter
        next_destination = self.request.GET.get('next', '')
        login_base_url = reverse('uchileedxlogin-login:login')
        encoded_next = urlquote_plus(next_destination)
        context['target_url'] = f"{login_base_url}?next={encoded_next}"
        
        return context
