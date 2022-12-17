from rest_framework import serializers
from .models import Users
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.exceptions import AuthenticationFailed


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model= Users
        fields= '__all__'
        depth=1

        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance


class UserUpdateProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users

        fields = ['email','mobile_no']




class ChangePasswordSerializer(serializers.Serializer):
    model = Users


    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)


class ResetPasswordEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)
    url = serializers.CharField(max_length=50)

    class Meta:
        fields = ['email', 'url']


class setNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)
    token = serializers.CharField(write_only=True)
    user_id = serializers.CharField(write_only=True)

    class Meta:
        fields = ['password', 'token', 'user_id']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            user_id = attrs.get('user_id')
            # id = force_str(urlsafe_base64_decode(uidb64))
            user = Users.objects.get(user_id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)
            user.set_password(password)
            user.save()
            return (user)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)