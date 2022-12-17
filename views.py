from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework import generics, permissions
from rest_framework.generics import GenericAPIView
from rest_framework.authtoken.serializers import AuthTokenSerializer
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import DjangoUnicodeDecodeError
from knox.auth import AuthToken
from .serializers import UserSerializer,UserUpdateProfileSerializer, ChangePasswordSerializer,ResetPasswordEmailSerializer,setNewPasswordSerializer
from . import models
from django.http import JsonResponse
from rest_framework.permissions import IsAuthenticated
from django.contrib.sites.shortcuts import get_current_site
from rest_framework.parsers import JSONParser
from rest_framework import status
from .models import Users
from .utils import Util



# Create your views here.

@api_view(['POST'])
def login_api(request):
    serializer = AuthTokenSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.validated_data['user']
    _, token = AuthToken.objects.create(user)

    return Response({
        'user_info': {
            'id': user.user_id,
            'username': user.username,
            'email': user.email,
            'created_at':user.created_at,

        },
        'token': token
    })



class updateProfile(GenericAPIView):
    permission_classes = [IsAuthenticated]


    def post(self, request):
        if request.method == 'POST':
            # variable_data = JSONParser().parse(request)
            variable_serializer = UserUpdateProfileSerializer(self.request.user, data=request.data)
            if variable_serializer.is_valid():
                variable_serializer.save()
                return JsonResponse(variable_serializer.data, status=status.HTTP_200_OK)
            return JsonResponse(variable_serializer.errors, status=status.HTTP_400_BAD_REQUEST)









class index(APIView):
    permission_classes = [IsAuthenticated]


    def get(self, request):
        if request.method == 'GET':
            queryset = models.Users.objects.all()
            user_serializer = UserSerializer(queryset, many=True)

            return JsonResponse(user_serializer.data, safe=False)



class ChangePasswordView(generics.UpdateAPIView):



    serializer_class = ChangePasswordSerializer
    model = Users
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class requestPasswordResetEmail(GenericAPIView):
    serializer_class = ResetPasswordEmailSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        email = request.data['email']
        # front end next page url
        url = request.data['url']
        error_msg = ['Please enter a valid email address']
        if Users.objects.filter(email=email).exists():
            user = Users.objects.get(email=email)
            user_id = user.user_id
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request=request).domain
            # relativeLink = reverse('password_reset', kwargs={'user_id': user_id, 'token': token})
            # absurl = 'http://' + current_site + relativeLink
            email_body = 'Hello, \n Use below link to reset your password \n' + url + '?u=' + str(
                user_id) + '&k=' + token
            data = {'email_body': email_body, 'email_subject': 'Reset your password', 'to_email': user.email}
            Util.send_email(data)
            return Response({'Success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)
        return Response({'email': error_msg}, status=status.HTTP_422_UNPROCESSABLE_ENTITY)


class passwordTokenCheckApi(GenericAPIView):
    def post(self, request):
        global user
        try:
            user_id = request.data['user_id']
            token = request.data['token']
            user = Users.objects.get(user_id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, please request a new one'},
                                status=status.HTTP_401_UNAUTHORIZED)
            return Response({'Success': True, 'message': 'Credentials valid', 'user_id': user_id, 'token': token},
                            status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            if not PasswordResetTokenGenerator().check_token(user):
                return Response({'error': 'Token is not valid, please request a new one'},
                                status=status.HTTP_401_UNAUTHORIZED)




class setNewPassword(GenericAPIView):
    serializer_class = setNewPasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'Success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)