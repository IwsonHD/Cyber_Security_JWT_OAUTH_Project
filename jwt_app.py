import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
import requests

countryWhiteList = ['Poland','France', 'Germany', 'England']
# Create Flask application
app = Flask(__name__)

# Configure Flask app
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique=True)
    password = db.Column(db.String(80))
    role = db.Column(db.String(20))

class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100))
    owner_id = db.Column(db.String(50))
    content = db.Column(db.String(200))
    country_availability = db.Column(db.String(50), nullable=True)

def abac_policy(current_user, resource, action):
    if current_user.role == 'admin':
        return True
    if current_user.role != 'admin' and action == 'read':
        return True
    return False

def get_country_from_ip(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        country = data.get('country')
        return country
    except Exception as e:
        print("Error occurred while fetching country from IP:", e)
        return None

# Role-based access decorator
def auth_guard(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = None
            if 'x-access-token' in request.headers:
                token = request.headers['x-access-token']

            if not token:
                return jsonify({'message': 'Token is missing !!'}), 401

            try:
                data = jwt.decode(token, app.config['SECRET_KEY'])
                current_user = User.query.filter_by(public_id=data['public_id']).first()

                if role is not None and role != current_user.role:
                    return jsonify({'message': 'Unauthorized access !!'}), 403

            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'Token is expired !!'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'message': 'Invalid token !!'}), 401

            return f(current_user, *args, **kwargs)

        return decorated_function

    return decorator

def abac_guard(action):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = request.headers.get('x-access-token')
            if not token:
                return jsonify({'message': 'Token is missing !!'}), 401

            try:
                data = jwt.decode(token, app.config['SECRET_KEY'])
                current_user = User.query.filter_by(public_id=data['public_id']).first()
                resource_id = kwargs.get('id')
                resource = Resource.query.filter_by(id=resource_id).first()

                if not resource:
                    return jsonify({'message': 'Resource not found !!'}), 404

                user_country = get_country_from_ip(request.remote_addr)

                if user_country not in countryWhiteList:
                    return jsonify({'message': 'Access denied. Only users from Poland can access this resource.'}), 403

                if not abac_policy(current_user, resource, action):
                    return jsonify({'message': 'Access denied !!'}), 403

            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'Token is expired !!'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'message': 'Invalid token !!'}), 401

            return f(current_user, resource, *args, **kwargs)

        return decorated_function

    return decorator

@app.route('/users', methods=['GET'])
def get_all_users():
    users = User.query.all()
    output = []
    for user in users:
        output.append({
            'public_id': user.public_id,
            'name': user.name,
            'email': user.email
        })

    return jsonify({'users': output}), 200

@app.route('/users/<string:id>', methods=['GET'])
@auth_guard()
def get_user(current_user, id):
    user = User.query.filter_by(public_id=id).first()
    if not user:
        return jsonify({'message': 'No user found !!'}), 404

    user_data = {
        'public_id': user.public_id,
        'name': user.name,
        'email': user.email
    }

    return jsonify({'user': user_data}), 200

@app.route('/users/<string:id>', methods=['DELETE'])
@auth_guard('admin')
def delete_user(current_user, id):
    user = User.query.filter_by(public_id=id).first()
    if not user:
        return jsonify({'message': 'No user found !!'}), 404

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'User deleted successfully !!'}), 200

@app.route('/users/<string:id>', methods=['PUT'])
@auth_guard('admin')
def update_user(current_user, id):
    user = User.query.filter_by(public_id=id).first()
    if not user:
        return jsonify({'message': 'No user found !!'}), 404

    data = request.json
    user.name = data.get('name')
    user.email = data.get('email')
    user.password = generate_password_hash(data.get('password'))
    user.role = data.get('role', 'user')

    db.session.commit()

    return jsonify({'message': 'User updated successfully !!'}), 200

@app.route('/users', methods=['POST'])
@auth_guard('admin')
def create_user(current_user):
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'user')  # Default role is 'user'

    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({'error': 'User already exists. Please Log in.'}), 202

    user = User(
        public_id=str(uuid.uuid4()),
        name=name,
        email=email,
        password=generate_password_hash(password),
        role=role
    )
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User created successfully.'}), 201

@app.route('/login', methods=['POST'])
def login():
    auth = request.json

    if not auth or not auth.get('email') or not auth.get('password'):
        return jsonify({'error': 'Could not verify'}), 401

    user = User.query.filter_by(email=auth.get('email')).first()

    if not user:
        return jsonify({'error': 'Could not verify'}), 401

    if check_password_hash(user.password, auth.get('password')):
        token = jwt.encode({
            'public_id': user.public_id,
            'exp': datetime.now() + timedelta(minutes=30)
        }, app.config['SECRET_KEY'])

        return jsonify({'token': token}), 201

    return jsonify({'error': 'Could not verify'}), 403

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'user')  # Default role is 'user'

    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({'error': 'User already exists. Please Log in.'}), 202

    user = User(
        public_id=str(uuid.uuid4()),
        name=name,
        email=email,
        password=generate_password_hash(password),
        role=role
    )
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'Successfully registered.'}), 201

@app.route('/resources/<int:id>', methods=['GET'])
@abac_guard('read')
def get_resource(current_user, id):
    resource = Resource.query.filter_by(id=id).first()
    if not resource:
        return jsonify({'message': 'No resource found !!'}), 404

    resource_data = {
        'public_id': resource.public_id,
        'name': resource.name,
        'content': resource.content
    }
    return jsonify({'resource': resource_data}), 200

@app.route('/resources/<int:id>', methods=['DELETE'])
@abac_guard('delete')
def delete_resource(current_user, id):
    resource = Resource.query.filter_by(id=id).first()
    if not resource:
        return jsonify({'message': 'No resource found !!'}), 404

    db.session.delete(resource)
    db.session.commit()

    return jsonify({'message': 'Resource deleted successfully !!'}), 200
@app.route('/resources', methods=['GET'])
def get_all_resources():
    resources = Resource.query.all()
    output = []
    for resource in resources:
        output.append({
            'public_id': resource.public_id,
            'name': resource.name,
            'content': resource.email
        })

    return jsonify({'users': output}), 200

def initialize_resources():
    resources = [
        {
            'name': 'Sample Resource 1',
            'content': 'Content of Sample Resource 1',
            'country_availability': 'Poland'
        },
        {
            'name': 'Sample Resource 2',
            'content': 'Content of Sample Resource 2',
            'country_availability': 'France'
        },
        {
            'name': 'Sample Resource 3',
            'content': 'Content of Sample Resource 3',
            'country_availability': 'Germany'
        }
    ]

    for resource_data in resources:
        resource = Resource(
            public_id=str(uuid.uuid4()),
            name=resource_data['name'],
            content=resource_data['content'],
            country_availability=resource_data['country_availability']
        )
        db.session.add(resource)

    db.session.commit()
    
@app.route('/resources', methods=['POST'])
@abac_guard('add')
def create_resource(current_user):
    data = request.json
    name = data.get('name')
    content = data.get('content')
    country_availability = data.get('country_availability')
    owner_id = current_user.pulic_id
    
    resource = Resource.query.filter_by(name=name).first()
    if resource:
        return jsonify({'error': 'Data already exists.'}), 202

    resource = Resource(
		public_id=str(uuid.uuid4()),
    	name = name,
    	owner_id = owner_id,
    	content = content,
   	 	country_availability = country_availability
	)

    db.session.add(resource)
    db.session.commit()

    return jsonify({'message': 'User created successfully.'}), 201


if __name__ == "__main__":
	with app.app_context():
		db.create_all()
    
	app.run(debug=False, port=5001)
	initialize_resources()
