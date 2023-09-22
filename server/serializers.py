from rest_framework import serializers
from django.contrib.auth.models import User

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode

class UserSerializer(serializers.ModelSerializer):
    class Meta(object):
        model = User
        fields = ['id', 'username', 'password', 'email']


class EmailSerializer(serializers.Serializer):
    """
    Reset Password Email Request Serializer.
    """

    email: serializers.EmailField()

    class Meta:
        fields = ["email",]


class ResetPasswordSerializer(serializers.Serializer):
    '''
    Reset password serializer
    '''

    password = serializers.CharField(
        write_only=True
    )

    class Meta:
        fields = ("password")
    
    def validate(self, data):
        # return super().validate(attrs)
        """
        Verify token and encoded_pk and then set new password.
        """
        password = data.get('password')
        token = self.context.get("kwargs").get("token")
        encoded_pk = self.context.get("kwargs").get("encoded_pk")

        if token is None or encoded_pk is None:
            raise serializers.ValidationError("Missing data.")
        
        pk = urlsafe_base64_decode(encoded_pk).decode()
        user = User.objects.get(pk=pk)
        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError('The reset token is invaid')
        
        user.set_password(password)
        user.save()
        return data