import os
from unittest import TestCase

from datetime import date

from books_app import app, db, bcrypt
from books_app.models import Book, Author, User, Audience
"""
Run these tests with the command:
python -m unittest books_app.auth.tests
"""

#################################################
# Setup
#################################################


def create_books():
    a1 = Author(name='Harper Lee')
    b1 = Book(title='To Kill a Mockingbird',
              publish_date=date(1960, 7, 11),
              author=a1)
    db.session.add(b1)

    a2 = Author(name='Sylvia Plath')
    b2 = Book(title='The Bell Jar', author=a2)
    db.session.add(b2)
    db.session.commit()


def create_user():
    password_hash = bcrypt.generate_password_hash('password').decode('utf-8')
    user = User(username='me1', password=password_hash)
    db.session.add(user)
    db.session.commit()


def login(client, username, password):
    return client.post('/login',
                       data=dict(username=username, password=password),
                       follow_redirects=True)


def logout(client):
    return client.get('/logout', follow_redirects=True)


#################################################
# Tests
#################################################


class AuthTests(TestCase):
    def setUp(self):
        """Executed prior to each test."""
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['DEBUG'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        db.drop_all()
        db.create_all()

    """Tests for authentication (login & signup)."""

    def test_signup(self):
        # - Make a POST request to /signup, sending a username & password
        # - Check that the user now exists in the database
        create_user()

        # Make POST request with data
        post_data = {'username': 'test_user', 'password': 'test'}
        self.app.post('/signup', data=post_data)

        newUser = User.query.filter_by(username='test_user').one()
        self.assertIsNotNone(newUser)

    def test_signup_existing_user(self):
        # - Create a user
        # - Make a POST request to /signup, sending the same username & password
        # - Check that the form is displayed again with an error message

        create_user()

        # Make POST request with data
        post_data = {'username': 'test_user', 'password': 'test'}
        self.app.post('/signup', data=post_data)

        post_data = {'username': 'test_user', 'password': 'test'}
        response = self.app.post('/signup', data=post_data)

        response_text = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("That username is taken. Please choose a different one.",
                      response_text)

    def test_login_correct_password(self):
        # - Create a user
        # - Make a POST request to /login, sending the created username & password
        # - Check that the "login" button is not displayed on the homepage

        create_user()

        response = login(self.app, 'me1', 'password')

        response_text = response.get_data(as_text=True)

        self.assertNotIn("login", response_text)

    def test_login_nonexistent_user(self):
        # - Make a POST request to /login, sending a username & password
        # - Check that the login form is displayed again, with an appropriate
        #   error message

        response = login(self.app, 'me1', 'password')

        response_text = response.get_data(as_text=True)

        self.assertIn("No user with that username. Please try again.",
                      response_text)

        self.assertIn('Enter your credentials', response_text)
        self.assertIn('Log In', response_text)

    def test_login_incorrect_password(self):
        # - Create a user
        # - Make a POST request to /login, sending the created username &
        #   an incorrect password
        # - Check that the login form is displayed again, with an appropriate
        #   error message
        create_user()

        response = login(self.app, 'me1', 'not the password')

        response_text = response.get_data(as_text=True)

        self.assertIn("Password doesn&#39;t match. Please try again.",
                      response_text)

        self.assertIn('Enter your credentials', response_text)
        self.assertIn('Log In', response_text)

    def test_logout(self):
        # - Create a user
        # - Log the user in (make a POST request to /login)
        # - Make a GET request to /logout
        # - Check that the user's name does not appear on the homepage

        create_user()

        login(self.app, 'me1', 'not the password')

        response = logout(self.app)

        response_text = response.get_data(as_text=True)

        self.assertNotIn("me1", response_text)
