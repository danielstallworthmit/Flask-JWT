from flask import Flask
# current_identity is like current_user
from flask_jwt import JWT, jwt_required, current_identity
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_restful import Api, Resource, reqparse, marshal_with, fields
from flask_bcrypt import Bcrypt
from datetime import datetime

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.debug = True
app.config['SECRET_KEY'] = 'super-secret'

api = Api(app)

db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = "postgres://localhost/flask-jwt"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text)
    password = db.Column(db.Text)
    posts = db.relationship('Post', backref='user', lazy='joined')
    created = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self,username, password):
        self.username = username
        self.password = bcrypt.generate_password_hash(password).decode('UTF-8')


class Post(db.Model):
    __tablename__ = 'posts'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text)
    body = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self,title, body, user_id):
        self.title = title
        self.body = body
        self.user_id = user_id

post_user_fields = {
    'id': fields.Integer,
    'username': fields.String,
}

post_fields= {
    'id': fields.Integer,
    'title': fields.String,
    'body': fields.String,
    'created': fields.DateTime(dt_format='rfc822'),
    'user': fields.Nested(post_user_fields)
}

user_fields= {
    'id': fields.Integer,
    'username': fields.String,
     # don't want people seeing the password...
    'posts': fields.Nested(post_fields),
}

@api.resource('/signup')
class SignupAPI(Resource):
    @marshal_with(user_fields)
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, help='username')
        parser.add_argument('password', type=str, help='password')
        args = parser.parse_args()
        try:
            new_user = User(args['username'], args['password'])
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError as e:
            return "Username already exists"
        return new_user


@api.resource('/users/<int:id>')
class UserAPI(Resource):

    @jwt_required()
    @marshal_with(user_fields)
    def get(self, id):
        return current_identity

    @marshal_with(user_fields)
    @jwt_required()
    def put(self, id):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, help='username')
        parser.add_argument('password', type=str, help='password')
        args = parser.parse_args()
        current_identity.name = args['username']
        current_identity.password = bcrypt.generate_password_hash(args['password']).encode('utf-8')
        db.session.add(current_identity)
        db.session.commit()
        return found_user

    @jwt_required()
    def delete(self, id):
        db.session.delete(current_identity)
        db.session.commit()
        return None, 204


@api.resource('/users/<int:user_id>/posts')
class PostsAPI(Resource):
    @marshal_with(post_fields)
    @jwt_required()
    def get(self, user_id):
        return current_identity.posts

    @marshal_with(post_fields)
    def post(self, user_id):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, help='Name')
        args = parser.parse_args()
        new_post = Post(args['name'], user_id)
        db.session.add(new_post)
        db.session.commit()
        return new_post

@api.resource('/users/<int:user_id>/posts/<int:id>')
class PostAPI(Resource):
    @jwt_required()
    @marshal_with(post_fields)
    def get(self, user_id, id):
        return Post.query.get_or_404(id)

    @marshal_with(post_fields)
    @jwt_required()
    def put(self, user_id, id):
        found_post = Post.query.get_or_404(id)
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, help='Name')
        args = parser.parse_args()
        found_post.name = args['name']
        db.session.add(found_post)
        db.session.commit()
        return found_post

    @jwt_required()
    def delete(self, user_id, id):
        post = Post.query.get_or_404(id)
        db.session.delete(post)
        db.session.commit()
        return None, 204

# get's run when a post is made to /auth with application/json as a content type
def authenticate(username, password):
    user = User.query.filter(User.username == username).first()
    if bcrypt.check_password_hash(user.password, password):
        return user

# get's run when jwt_required
def identity(payload):
    user_id = payload['identity']
    return User.query.get_or_404(user_id)

jwt = JWT(app, authenticate, identity)


if __name__ == '__main__':
    app.run()