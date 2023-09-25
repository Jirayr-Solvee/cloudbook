from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.models import User
from .models import Section, Book


class SectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Section
        fields = ('id', 'title', 'book')


class SectionEditSerializer(serializers.ModelSerializer):
    new_title = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = Section
        fields = ('id', 'new_title')


class BookCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Book
        fields = ('id', 'title')

    def create(self, validated_data):
        title = validated_data['title']
        author = self.context['request'].user
        return Book.objects.create(title=title, author=author)


class UserSerializer(serializers.ModelSerializer):

    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password]
    )

    class Meta:
        model = User
        fields = ('id', 'username', 'password')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

    def validate(self, data):
        return super(UserSerializer, self).validate(data)
