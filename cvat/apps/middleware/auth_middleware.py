import os
import jwt
import requests
from django.http import HttpResponseRedirect, HttpResponse, JsonResponse

from cvat.apps.engine.log import slogger


class AuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if "/api/custom/login" in request.build_absolute_uri():
            print(f"[{self.__class__.__name__ }] ignore auth check")
            response = self.get_response(request)
            return response
        
        # if "/api/users" in request.build_absolute_uri():
        #     response = self.get_response(request)
        #     return response

        # slogger.glob.info
        print(f"[{self.__class__.__name__ }] Request URL: {request.build_absolute_uri()}")

        # get access_token, refresh_token from Cookie
        access_token = request.COOKIES.get('access_token')
        refresh_token = request.COOKIES.get('refresh_token')

        # 1. check access_token is valid or expired
        if access_token == 'ok':
            print(f"[{self.__class__.__name__ }] verify ok")
            response = self.get_response(request)
            return response

        # 2. call refresh_token to update access_token
        if refresh_token == 'update':
            print(f"[{self.__class__.__name__ }] call refresh_token to update access_token")
            domain = request.get_host()
            response = self.get_response(request)
            response.set_cookie(
                key="access_token",
                value="ok",
                # domain=f".{domain}" #何時需要加何時不用加?
            )
            return response

        # 3. relogin
        print(f"[{self.__class__.__name__ }] refresh fail, need to relogin")
        response_data = {
            'error': 'No permission',
            'message': 'You do not have permission to access this resource. Please relogin.'
        }
        return JsonResponse(response_data, status=401)

        # response = self.get_response(request)
        # return response