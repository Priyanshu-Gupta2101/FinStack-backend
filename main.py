"""
FinStack Task Management System Backend
A secure Flask-based REST API for task management
"""

import os
import datetime
import uuid
from functools import wraps
from typing import Dict

from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS, cross_origin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func
from marshmallow import Schema, fields, validate, ValidationError
import re

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'udhshfiucudsfbcixhvisdbvisdbvs')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///finstack_tasks.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'xsjfbwvubrgvdvbckbvsdbvewdvblkvl')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=24)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# Updated CORS configuration to handle Angular preflight requests
cors_origins = os.environ.get('CORS_ORIGIN', 'http://localhost:4200,http://127.0.0.1:4200,http://localhost:3000').split(',')
CORS(app, 
     origins=cors_origins,
     methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
     allow_headers=['Content-Type', 'Authorization', 'Accept', 'Origin', 'X-Requested-With'],
     supports_credentials=True
)

@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = jsonify({})
        response.headers.add("Access-Control-Allow-Origin", request.headers.get('Origin', '*'))
        response.headers.add('Access-Control-Allow-Headers', "Content-Type,Authorization,Accept,Origin,X-Requested-With")
        response.headers.add('Access-Control-Allow-Methods', "GET,PUT,POST,DELETE,PATCH,OPTIONS")
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response


class User(db.Model):
    """User model for authentication and task assignment"""
    __tablename__ = 'users'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    assigned_tasks = db.relationship('Task', backref='assigned_user', lazy=True, foreign_keys='Task.contact_person_id')
    created_tasks = db.relationship('Task', backref='creator', lazy=True, foreign_keys='Task.created_by')

    def set_password(self, password: str) -> None:
        """Set password hash"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Check password against hash"""
        return check_password_hash(self.password_hash, password)

    def to_dict(self) -> Dict:
        """Convert user to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat()
        }


class Task(db.Model):
    """Task model with all required attributes"""
    __tablename__ = 'tasks'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    date_created = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False, index=True)
    entity_name = db.Column(db.String(200), nullable=False, index=True)
    task_type = db.Column(db.String(100), nullable=False, index=True)
    task_time = db.Column(db.DateTime, nullable=False, index=True)
    contact_person_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    note = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='open', nullable=False, index=True)
    created_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    def to_dict(self) -> Dict:
        """Convert task to dictionary"""
        return {
            'id': self.id,
            'date_created': self.date_created.isoformat(),
            'entity_name': self.entity_name,
            'task_type': self.task_type,
            'task_time': self.task_time.isoformat(),
            'contact_person': self.assigned_user.to_dict() if self.assigned_user else None,
            'note': self.note,
            'status': self.status,
            'created_by': self.creator.to_dict() if self.creator else None,
            'updated_at': self.updated_at.isoformat()
        }


class UserRegistrationSchema(Schema):
    """Schema for user registration validation"""
    username = fields.Str(required=True, validate=validate.Length(min=3, max=80))
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=8))
    full_name = fields.Str(required=True, validate=validate.Length(min=2, max=100))


class UserLoginSchema(Schema):
    """Schema for user login validation"""
    username = fields.Str(required=True)
    password = fields.Str(required=True)


class TaskCreateSchema(Schema):
    """Schema for task creation validation"""
    entity_name = fields.Str(required=True, validate=validate.Length(min=1, max=200))
    task_type = fields.Str(required=True, validate=validate.Length(min=1, max=100))
    task_time = fields.DateTime(required=True)
    contact_person_id = fields.Str(required=True)
    note = fields.Str(validate=validate.Length(max=1000))
    status = fields.Str(validate=validate.OneOf(['open', 'closed'])) 


class TaskUpdateSchema(Schema):
    """Schema for task update validation"""
    entity_name = fields.Str(validate=validate.Length(min=1, max=200))
    task_type = fields.Str(validate=validate.Length(min=1, max=100))
    task_time = fields.DateTime()
    contact_person_id = fields.Str()
    note = fields.Str(validate=validate.Length(max=1000))
    status = fields.Str(validate=validate.OneOf(['open', 'closed']))


def validate_json_input(schema_class):
    """Decorator to validate JSON input against schema"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method == 'OPTIONS':
                return f(*args, **kwargs)
                
            try:
                data = request.get_json()
                if not data:
                    return jsonify({'error': 'No JSON data provided'}), 400

                schema = schema_class()
                validated_data = schema.load(data)
                g.validated_data = validated_data
                return f(*args, **kwargs)
            except ValidationError as err:
                return jsonify({'error': 'Validation failed', 'details': err.messages}), 400
            except Exception as e:
                return jsonify({'error': 'Invalid JSON format'}), 400

        return decorated_function

    return decorator


def validate_uuid(uuid_string: str) -> bool:
    """Validate UUID format"""
    try:
        uuid.UUID(uuid_string)
        return True
    except ValueError:
        return False


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded', 'description': str(e.description)}), 429


@app.route('/api/auth/register', methods=['POST', 'OPTIONS'])
@cross_origin()
@validate_json_input(UserRegistrationSchema)
def register():
    """Register a new user"""
    if request.method == 'OPTIONS':
        return jsonify({}), 200
        
    data = g.validated_data

    if User.query.filter((User.username == data['username']) | (User.email == data['email'])).first():
        return jsonify({'error': 'Username or email already exists'}), 409

    user = User(
        username=data['username'],
        email=data['email'],
        full_name=data['full_name']
    )
    user.set_password(data['password'])

    try:
        db.session.add(user)
        db.session.commit()

        access_token = create_access_token(identity=user.id)

        return jsonify({
            'message': 'User registered successfully',
            'user': user.to_dict(),
            'access_token': access_token
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create user'}), 500


@app.route('/api/auth/login', methods=['POST', 'OPTIONS'])
@cross_origin()
@validate_json_input(UserLoginSchema)
def login():
    """User login"""
    if request.method == 'OPTIONS':
        return jsonify({}), 200
        
    data = g.validated_data

    user = User.query.filter_by(username=data['username']).first()

    if user and user.check_password(data['password']) and user.is_active:
        access_token = create_access_token(identity=user.id)
        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict(),
            'access_token': access_token
        }), 200

    return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/api/auth/me', methods=['GET', 'OPTIONS'])
@cross_origin()
@jwt_required()
def get_current_user():
    """Get current user info"""
    if request.method == 'OPTIONS':
        return jsonify({}), 200
        
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user or not user.is_active:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({'user': user.to_dict()}), 200


@app.route('/api/users', methods=['GET', 'OPTIONS'])
@cross_origin()
@jwt_required()
def get_users():
    """Get all active users for task assignment"""
    if request.method == 'OPTIONS':
        return jsonify({}), 200
        
    users = User.query.filter_by(is_active=True).all()
    return jsonify({
        'users': [user.to_dict() for user in users]
    }), 200


@app.route('/api/tasks', methods=['POST', 'OPTIONS'])
@cross_origin()
@jwt_required()
@validate_json_input(TaskCreateSchema)
def create_task():
    """Create a new task"""
    if request.method == 'OPTIONS':
        return jsonify({}), 200
        
    data = g.validated_data
    user_id = get_jwt_identity()

    contact_person = User.query.get(data['contact_person_id'])
    if not contact_person or not contact_person.is_active:
        return jsonify({'error': 'Invalid contact person'}), 400

    task = Task(
        entity_name=data['entity_name'],
        task_type=data['task_type'],
        task_time=data['task_time'],
        contact_person_id=data['contact_person_id'],
        note=data.get('note'),
        created_by=user_id
    )

    try:
        db.session.add(task)
        db.session.commit()
        return jsonify({
            'message': 'Task created successfully',
            'task': task.to_dict()
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create task'}), 500


@app.route('/api/tasks', methods=['GET', 'OPTIONS'])
@cross_origin()
@jwt_required()
def get_tasks():
    """Get tasks with filtering and sorting"""
    if request.method == 'OPTIONS':
        return jsonify({}), 200
        
    status = request.args.get('status')
    task_type = request.args.get('task_type')
    entity_name = request.args.get('entity_name')
    contact_person_id = request.args.get('contact_person_id')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')

    sort_by = request.args.get('sort_by', 'date_created')
    sort_order = request.args.get('sort_order', 'desc')

    page = int(request.args.get('page', 1))
    per_page = min(int(request.args.get('per_page', 20)), 100)

    query = Task.query

    if status:
        query = query.filter(Task.status == status)
    if task_type:
        query = query.filter(Task.task_type.ilike(f'%{task_type}%'))
    if entity_name:
        query = query.filter(Task.entity_name.ilike(f'%{entity_name}%'))
    if contact_person_id:
        if validate_uuid(contact_person_id):
            query = query.filter(Task.contact_person_id == contact_person_id)
    if date_from:
        try:
            date_from_dt = datetime.datetime.fromisoformat(date_from.replace('Z', '+00:00'))
            query = query.filter(Task.date_created >= date_from_dt)
        except ValueError:
            pass
    if date_to:
        try:
            date_to_dt = datetime.datetime.fromisoformat(date_to.replace('Z', '+00:00'))
            query = query.filter(Task.date_created <= date_to_dt)
        except ValueError:
            pass

    if hasattr(Task, sort_by):
        if sort_order.lower() == 'asc':
            query = query.order_by(getattr(Task, sort_by).asc())
        else:
            query = query.order_by(getattr(Task, sort_by).desc())

    try:
        tasks_paginated = query.paginate(
            page=page, per_page=per_page, error_out=False
        )

        return jsonify({
            'tasks': [task.to_dict() for task in tasks_paginated.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': tasks_paginated.total,
                'pages': tasks_paginated.pages,
                'has_next': tasks_paginated.has_next,
                'has_prev': tasks_paginated.has_prev
            }
        }), 200

    except Exception as e:
        return jsonify({'error': 'Failed to fetch tasks'}), 500


@app.route('/api/tasks/<task_id>', methods=['GET', 'OPTIONS'])
@cross_origin()
@jwt_required()
def get_task(task_id):
    """Get a specific task"""
    if request.method == 'OPTIONS':
        return jsonify({}), 200
        
    if not validate_uuid(task_id):
        return jsonify({'error': 'Invalid task ID format'}), 400

    task = Task.query.get(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404

    return jsonify({'task': task.to_dict()}), 200


@app.route('/api/tasks/<task_id>', methods=['PUT', 'OPTIONS'])
@cross_origin()
@jwt_required()
@validate_json_input(TaskUpdateSchema)
def update_task(task_id):
    """Update a task"""
    if request.method == 'OPTIONS':
        return jsonify({}), 200
        
    if not validate_uuid(task_id):
        return jsonify({'error': 'Invalid task ID format'}), 400

    task = Task.query.get(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404

    data = g.validated_data

    if 'contact_person_id' in data:
        contact_person = User.query.get(data['contact_person_id'])
        if not contact_person or not contact_person.is_active:
            return jsonify({'error': 'Invalid contact person'}), 400

    for field in ['entity_name', 'task_type', 'task_time', 'contact_person_id', 'note', 'status']:
        if field in data:
            setattr(task, field, data[field])

    try:
        db.session.commit()
        return jsonify({
            'message': 'Task updated successfully',
            'task': task.to_dict()
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update task'}), 500


@app.route('/api/tasks/<task_id>/status', methods=['PATCH', 'OPTIONS'])
@cross_origin()
@jwt_required()
def update_task_status(task_id):
    """Update task status only"""
    if request.method == 'OPTIONS':
        return jsonify({}), 200
        
    if not validate_uuid(task_id):
        return jsonify({'error': 'Invalid task ID format'}), 400

    task = Task.query.get(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404

    data = request.get_json()
    if not data or 'status' not in data:
        return jsonify({'error': 'Status is required'}), 400

    status = data['status']
    if status not in ['open', 'closed']:
        return jsonify({'error': 'Status must be either "open" or "closed"'}), 400

    task.status = status

    try:
        db.session.commit()
        return jsonify({
            'message': 'Task status updated successfully',
            'task': task.to_dict()
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update task status'}), 500


@app.route('/api/tasks/<task_id>', methods=['DELETE', 'OPTIONS'])
@cross_origin()
@jwt_required()
def delete_task(task_id):
    """Delete a task"""
    if request.method == 'OPTIONS':
        return jsonify({}), 200
        
    if not validate_uuid(task_id):
        return jsonify({'error': 'Invalid task ID format'}), 400

    task = Task.query.get(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404

    try:
        db.session.delete(task)
        db.session.commit()
        return jsonify({'message': 'Task deleted successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete task'}), 500


@app.route('/api/analytics/dashboard', methods=['GET', 'OPTIONS'])
@cross_origin()
@jwt_required()
def get_dashboard_analytics():
    """Get dashboard analytics"""
    if request.method == 'OPTIONS':
        return jsonify({}), 200
        
    try:
        total_tasks = Task.query.count()
        open_tasks = Task.query.filter_by(status='open').count()
        closed_tasks = Task.query.filter_by(status='closed').count()

        task_types = db.session.query(
            Task.task_type,
            func.count(Task.id).label('count')
        ).group_by(Task.task_type).all()

        user_tasks = db.session.query(
            User.full_name,
            func.count(Task.id).label('count')
        ).join(Task, User.id == Task.contact_person_id).group_by(User.id, User.full_name).all()

        return jsonify({
            'summary': {
                'total_tasks': total_tasks,
                'open_tasks': open_tasks,
                'closed_tasks': closed_tasks
            },
            'task_types': [{'type': t[0], 'count': t[1]} for t in task_types],
            'user_tasks': [{'user': u[0], 'count': u[1]} for u in user_tasks]
        }), 200

    except Exception as e:
        return jsonify({'error': 'Failed to fetch analytics'}), 500


@app.route('/api/health', methods=['GET', 'OPTIONS'])
@cross_origin()
def health_check():
    """Health check endpoint"""
    if request.method == 'OPTIONS':
        return jsonify({}), 200
        
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'version': '1.0.0'
    }), 200


with app.app_context():
    db.create_all()
    
    if not User.query.first():
        admin_user = User(
            username='admin',
            email='admin@finstack.com',
            full_name='System Administrator'
        )
        admin_user.set_password('admin123')
        db.session.add(admin_user)
        db.session.commit()
        print("Default admin user created: admin/admin123")


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)