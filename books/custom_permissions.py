from rest_framework import permissions
from .models import Book


class IsAuthorPermission(permissions.BasePermission):
    message = "Only authors can perform this action."

    def has_permission(self, request, view):
        if 'book_id' in request.data:
            book = Book.objects.get(id=request.data['book_id'])
            return book.author == request.user
        return False

    def has_object_permission(self, request, view, obj):
        return obj.book.author == request.user


class IsAuthorOrCollaboratorPermission(permissions.BasePermission):
    message = "Only the author or collaborators can edit this section."

    def has_object_permission(self, request, view, obj):
        book = obj.book
        return (
            book.author == request.user
            or request.user in book.collaborators.all()
        )
