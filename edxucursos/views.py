#!/usr/bin/env python
# -- coding: utf-8 --

from django.conf import settings
from django.core.exceptions import ValidationError
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.db import transaction
from django.http import HttpResponseRedirect, HttpResponseForbidden, Http404, HttpResponseNotFound
from django.shortcuts import render
from django.urls import reverse
from django.views.generic.base import View
from django.http import HttpResponse
from uchileedxlogin.models import EdxLoginUser, EdxLoginUserCourseRegistration
from models import EdxUCursosTokens
from urllib import urlencode
from itertools import cycle
from opaque_keys.edx.keys import CourseKey
from opaque_keys import InvalidKeyError
from requests.auth import HTTPBasicAuth
from courseware.courses import get_course_by_id, get_course_with_access
from courseware.access import has_access
from util.json_request import JsonResponse, JsonResponseBadRequest

import json
import requests
import uuid
import unidecode
import logging
import sys
import unicodecsv as csv
import time

logger = logging.getLogger(__name__)


class EdxUCursosLoginRedirect(View):
    def get(self, request):
        ticket = request.GET.get('ticket', "")
        logger.info('ticket: ' + ticket)
        if request.user.is_authenticated():
            try:
                edxucursostoken = EdxUCursosTokens.objects.get(
                    user=request.user)
                token = edxucursostoken.token
                logger.info('User logged')
                return HttpResponse(
                    EdxUCursosLoginRedirect.get_callback_url(request, token))
            except EdxUCursosTokens.DoesNotExist:
                logger.info('No exists token for user logged')
                pass

        user_data = self.get_data_ticket(ticket)
        if user_data['result'] == 'error':
            logger.info('Data error')
            logger.info(user_data)
            return HttpResponseNotFound('Error with ucursos api - ticket')

        if self.verify_caducity(user_data):
            logger.info('Ticket caducado: ' + ticket)
            return HttpResponseNotFound('Expired ticket')

        rut = str(user_data['pers_id'])
        rut_dv = self.digito_verificador(rut)
        while len(rut) < 9:
            rut = "0" + rut
        rut = rut + rut_dv
        edxlogin_user = self.get_edxlogin_user(rut)
        if edxlogin_user:
            logger.info('Exists EdxLogin_User: ' + edxlogin_user.user.username)
            token = self.get_or_create_token(edxlogin_user.user)
            return HttpResponse(
                EdxUCursosLoginRedirect.get_callback_url(request, token))
        else:
            logger.info('User not Found: ' + rut)
            return HttpResponseNotFound('User not Found')

    def get_data_ticket(self, ticket):
        parameters = {
            'ticket': ticket
        }
        result = requests.get(
            settings.EDXUCURSOS_VERIFY_TICKET,
            params=urlencode(parameters),
            headers={
                'content-type': 'application/json'})
        if result.status_code == 200:
            data = json.loads(result.text)
            data['result'] = 'success'
            return data
        return {'result': 'error'}

    def verify_caducity(self, data):
        aux_time = time.time()
        if (aux_time - data["time"]) > 60:
            return True
        return False

    def get_edxlogin_user(self, rut):
        try:
            edxlogin_user = EdxLoginUser.objects.get(run=rut)
            return edxlogin_user
        except EdxLoginUser.DoesNotExist:
            pass

        return False

    def digito_verificador(self, run):
        rut = reversed(map(int, run))
        m = [2, 3, 4, 5, 6, 7]

        d = sum([n * m[i % 6] for i, n in enumerate(rut)])
        d %= 11

        if (d == 1):
            d = 'K'
        else:
            d = 11 - d
        return str(d)

    def login_user(self, request, edxlogin_user):
        """
        Get or create the user and log him in.
        """
        login(
            request,
            edxlogin_user.user,
            backend="django.contrib.auth.backends.AllowAllUsersModelBackend",
        )

    def get_or_create_token(self, user):
        token = str(uuid.uuid4())
        while EdxUCursosTokens.objects.filter(token=token).exists():
            token = str(uuid.uuid4())
        try:
            edxucursostoken = EdxUCursosTokens.objects.get(user=user)
            edxucursostoken.token = token
            edxucursostoken.save()
        except EdxUCursosTokens.DoesNotExist:
            EdxUCursosTokens.objects.create(token=token, user=user)

        return token

    @staticmethod
    def get_callback_url(request, token):
        """
        Get the callback url
        """
        url = request.build_absolute_uri(reverse('edxucursos-login:callback'))
        return '{}?token={}'.format(url, token)


class EdxUCursosCallback(View):
    def get(self, request):
        token = request.GET.get('token', "")
        logger.info('token: ' + token)
        try:
            edxucursostoken = EdxUCursosTokens.objects.get(token=token)
            login(
                request,
                edxucursostoken.user,
                backend="django.contrib.auth.backends.AllowAllUsersModelBackend",
            )
            return HttpResponseRedirect("/dashboard")
        except (EdxUCursosTokens.DoesNotExist, Exception):
            return HttpResponseNotFound('Logging Error: Token no Exists')
