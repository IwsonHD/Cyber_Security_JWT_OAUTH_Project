import os
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps

# Create Flask application
app = Flask(__name__)

# Configure Flask app
app.config['SECRET_KEY'] = str(os.getenv('SECRET_KEY'))
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
	role = db.Column(db.String(50))


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
			'exp': datetime.utcnow() + timedelta(minutes=30)
		}, app.config['SECRET_KEY'])

		return jsonify({'token': token.decode('UTF-8')}), 201

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


if __name__ == "__main__":
	with app.app_context():
		db.create_all()
	app.run(debug=True)
