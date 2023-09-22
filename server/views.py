from rest_framework.decorators import api_view
from rest_framework.response import Response

from .serializers import UserSerializer, EmailSerializer, ResetPasswordSerializer
from rest_framework import status
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User

from django.shortcuts import get_object_or_404

from .send_email import send

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

@api_view(['GET'])
def sending(request):
    try:
        send('trying2', 'sending', ['codedeveloper47@gmail.com'])
    except Exception as e:
        return Response(f"An error occurred while sending the email: {str(e)}", status=status.HTTP_400_BAD_REQUEST)
    
    
    return Response({"hi": 'hello'})


@api_view(['POST'])
def login(request):
    user = get_object_or_404(User, username=request.data['username'])
    if not user.check_password(request.data['password']):
        return Response({'detail': 'Not Found'}, status=status.HTTP_400_BAD_REQUEST)
    token, created = Token.objects.get_or_create(user=user)
    serializer = UserSerializer(instance=user)
    return Response({"token": token.key, "user": serializer.data})


@api_view(['POST'])
def signup(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        user = User.objects.get(username=request.data.get('username'))
        user.set_password(request.data['password'])
        user.save()
        token = Token.objects.create(user=user)
        return Response({"token": token.key, "user": serializer.data})
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def forgotPassword(request):
    '''
    Request for Password Reset Link
    '''
    serializer = EmailSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    email = request.data["email"]
    print(email)

    user = User.objects.filter(email=email).first()

    if user:
        encoded_pk = urlsafe_base64_encode(force_bytes(user.pk))
        token = PasswordResetTokenGenerator().make_token(user)
        reset_url = reverse('reset-password', kwargs={'encoded_pk':encoded_pk, 'token': token})

        reset_link = f"localhost:8000{reset_url}"

        return Response({'message': reset_link}, status=status.HTTP_200_OK)
    
    return Response({'message': 'User does not exist'})


@api_view(['PATCH'])
def reset(request, *args, **kwargs):
    serializer = ResetPasswordSerializer(data=request.data, context={"kwargs": kwargs})

    serializer.is_valid(raise_exception=True)
    return Response({'message': 'Password suceesfully updated'})

from rest_framework.decorators import authentication_classes, permission_classes
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated


@api_view(['GET'])
@authentication_classes([SessionAuthentication, TokenAuthentication])
@permission_classes([IsAuthenticated])
def test_token(request):
    return Response("Passed for {}".format(request.user.email))


@api_view(['GET'])
@authentication_classes([SessionAuthentication, TokenAuthentication])
@permission_classes([IsAuthenticated])
def logout(request):
    request.user.auth_token.delete()
    
    return Response("User successfully logout!")


