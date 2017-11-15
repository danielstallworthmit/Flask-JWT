from flask import Flask, json
from flask_testing import TestCase
from app import db, identity, authenticate, User, Post, jwt
import unittest

class MyTest(TestCase):

    def create_app(self):
        app = Flask(__name__)
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite://testing"
        return app

    def setUp(self):
        db.create_all()
        new_user = User('eschoppik','secret')
        db.session.add(new_user)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_signup(self):
        # post /signup with users
        pass

    def test_login(self):
        pass

    def test_authorization(self):
        # create a puppy

        # login
        pass


if __name__ == '__main__':
    unittest.main()