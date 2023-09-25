from django.db import models
from django.contrib.auth.models import User


class Book(models.Model):
    title = models.CharField(max_length=255)
    author = models.ForeignKey(
        User, related_name="authored_books", on_delete=models.CASCADE
    )
    collaborators = models.ManyToManyField(
        User, related_name="collaborative_books"
    )

    def __str__(self):
        return self.title


class Section(models.Model):
    title = models.CharField(max_length=255)
    parent = models.ForeignKey(
        'self', null=True, blank=True, on_delete=models.CASCADE
    )
    book = models.ForeignKey(
        Book, null=True, blank=True, on_delete=models.CASCADE
    )

    def __str__(self):
        return self.title
