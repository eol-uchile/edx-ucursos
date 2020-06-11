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
        logout(request)
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
            from rest_framework_jwt.settings import api_settings

            jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

            payload = self.get_payload(edxlogin_user.user)
            token = jwt_encode_handler(payload)
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
        logger.info(result.text)
        if result.text != 'null':
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
        return token

    def get_payload(self, user):
        from rest_framework_jwt.settings import api_settings
        from datetime import datetime as dt
        import datetime
        payload = {'username': user.username,
                    'user_id': user.id,
                    'exp': dt.utcnow() + datetime.timedelta(seconds=settings.EDXCURSOS_EXP_TIME)}

        if api_settings.JWT_AUDIENCE is not None:
            payload['aud'] = api_settings.JWT_AUDIENCE

        return payload

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
        logout(request)
        import jwt
        try:
            payload = self.decode_token(token)
        except jwt.ExpiredSignatureError:
            return HttpResponseNotFound('Caducity Token')
        except Exception:
            return HttpResponseNotFound('Decoding failure')

        try:
            login_user = User.objects.get(id=payload['user_id'])
            login(
                request,
                login_user,
                backend="django.contrib.auth.backends.AllowAllUsersModelBackend",
            )
            request.session.set_expiry(0)
            return HttpResponseRedirect("/dashboard")
        except (User.DoesNotExist, Exception):
            return HttpResponseNotFound('Logging Error or User no Exists')

    def decode_token(self, token):
        from rest_framework_jwt.settings import api_settings
        from rest_framework_jwt.utils import jwt_get_secret_key 
        import jwt

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