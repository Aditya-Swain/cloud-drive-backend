import jwt
from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model

class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None

        try:
            prefix, token = auth_header.split(' ')
            if prefix.lower() != 'bearer':
                raise AuthenticationFailed('Invalid token prefix')

            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = get_user_model().objects.get(id=payload['user_id'])
            return (user, None)

        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired')
        except jwt.DecodeError:
            raise AuthenticationFailed('Invalid token')
        except get_user_model().DoesNotExist:
            raise AuthenticationFailed('User not found')
