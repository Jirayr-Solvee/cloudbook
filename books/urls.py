from django.urls import path
from .views import (
    RegisterView, SectionCreateView,
    SectionEditView, CustomLoginView,
    ManageCollaboratorView, BookCreateView
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', CustomLoginView.as_view(), name='login'),
    path('book/', BookCreateView.as_view(), name='book-create'),
    path('section/', SectionCreateView.as_view(), name='section-create'),
    path('section/<int:pk>/', SectionEditView.as_view(), name='section-edit'),
    path(
        'manage-collaborator/',
        ManageCollaboratorView.as_view(),
        name='manage-collaborator'
    ),
]
