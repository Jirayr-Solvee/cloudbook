from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth.models import User
from .models import Book, Section
from rest_framework.authtoken.models import Token


class BookAPITestCase(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser', password='testpass'
            )
        self.user2 = User.objects.create_user(
            username='testuser2', password='testpass2'
            )
        self.book = Book.objects.create(
            title='Test Book', author=self.user
            )
        self.section = Section.objects.create(
            title='Test Section', book=self.book
            )
        self.login()
        token, _ = Token.objects.get_or_create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

    def login(self, username='testuser', password='testpass'):
        self.client.login(username=username, password=password)

    def test_register_user(self):
        url = reverse('register')
        data = {
            'username': 'newuser',
            'password': 'newpassword'
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(username='newuser').exists())

    def test_registration_existing_username(self):
        User.objects.create_user(
            username='existinguser', password='existingpassword'
            )
        url = reverse('register')
        data = {'username': 'existinguser', 'password': 'newpassword'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_registration_short_password(self):
        url = reverse('register')
        data = {'username': 'shortpassuser', 'password': 's'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_registration_no_password(self):
        url = reverse('register')
        data = {'username': 'nopassuser'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_successful(self):
        url = reverse('login')
        data = {'username': 'testuser', 'password': 'testpass'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_login_incorrect_password(self):
        url = reverse('login')
        data = {'username': 'testuser', 'password': 'wrongpass'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_non_existing_user(self):
        url = reverse('login')
        data = {'username': 'nonexistentuser', 'password': 'testpass'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_book(self):
        url = reverse('book-create')
        data = {'title': 'Another Book'}
        response = self.client.post(
            url, data, format='json'
            )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(Book.objects.filter(title='Another Book').exists())

    def test_create_section(self):
        url = reverse('section-create')
        data = {
            'title': 'Another Section', 'book_id': self.book.id
            }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(Section.objects.filter(
            title='Another Section'
            ).exists())

    def test_create_book_unauthenticated(self):
        self.client.logout()
        url = reverse('book-create')
        data = {'title': 'Another Test Book'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.login()

    def test_edit_section(self):
        url = reverse('section-edit', kwargs={'pk': self.section.id})
        data = {'new_title': 'Edited Test Section'}
        response = self.client.patch(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.section.refresh_from_db()
        self.assertEqual(self.section.title, 'Edited Test Section')

    def test_manage_collaborator_add(self):
        url = reverse('manage-collaborator')
        data = {'username': 'testuser2', 'book_id': self.book.id}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(self.user2, self.book.collaborators.all())

    def test_manage_collaborator_remove(self):
        self.book.collaborators.add(self.user2)
        url = reverse('manage-collaborator')
        data = {'username': 'testuser2', 'book_id': self.book.id}
        response = self.client.delete(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotIn(self.user2, self.book.collaborators.all())
