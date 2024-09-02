# from rest_framework import serializers
# from .models import User, PasswordHistory
# import re
# class UserSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         fields = ['id', 'name', 'email', 'password']
#         extra_kwargs = {'password': {'write_only': True}}
#
#     def validate_password(self,value):
#         if len(value) < 8:
#             raise serializers.ValidationError("Password must be at least 8 characters long")
#
#         if not re.search(r'[A-Z]', value):
#             raise serializers.ValidationError("Password must contain at least one uppercase letter ")
#
#         if not re.search(r'[a-z]', value):
#             raise serializers.ValidationError("Password must contain at least one lowercase letter ")
#
#         if not re.search(r'\d', value):
#             raise serializers.ValidationError("Password must contain atleast one digit ")
#
#         if not re.search(r'[!@#$%^&*(),?":.<>|{}]', value):
#             raise serializers.ValidationError("Password must contain at least one special character")
#
#         return value
#
#     def create(self, validated_data):
#         user = User.objects.create_user(**validated_data)
#         PasswordHistory.objects.create(user=user, old_password=user.password)
#         return user

from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'emp_id', 'email', 'password', 'name', 'role']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            name=validated_data.get('name', ''),
            emp_id =validated_data.get('emp_id',''),
            role=validated_data.get('role', 'User')
        )
        return user