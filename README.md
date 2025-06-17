# FinStack Task Management System Backend

A secure, scalable Flask-based REST API for task management with user authentication, comprehensive task CRUD operations, and analytics dashboard.

## Features

### 🔐 Authentication & Authorization
- JWT-based authentication with 24-hour token expiration
- Secure password hashing using Werkzeug
- User registration and login endpoints
- Protected routes with JWT middleware

### 📋 Task Management
- Create, read, update, and delete tasks
- Task assignment to users
- Status tracking (open/closed)
- Advanced filtering and sorting
- Pagination support
- Bulk status updates

### 👥 User Management
- User registration with validation
- User profile management
- Active user listing for task assignment
- Full name and contact information

### 📊 Analytics Dashboard
- Task summary statistics
- Task type distribution
- User task assignments
- Real-time dashboard metrics

### 🔧 Additional Features
- CORS support for frontend integration
- Input validation with Marshmallow schemas
- Error handling and logging
- Health check endpoint
- Database migrations support

## Technology Stack

- **Framework**: Flask 2.x
- **Database**: SQLite (configurable to PostgreSQL/MySQL)
- **ORM**: SQLAlchemy with Flask-SQLAlchemy
- **Authentication**: Flask-JWT-Extended
- **Validation**: Marshmallow
- **CORS**: Flask-CORS
- **Security**: Werkzeug password hashing

## Installation

### Prerequisites
- Python 3.8+
- pip (Python package manager)

### Setup Instructions

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd finstack-backend
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set environment variables**
   ```bash
   # Create .env file
   SECRET_KEY=your-super-secret-key-here
   JWT_SECRET_KEY=your-jwt-secret-key-here
   DATABASE_URL=sqlite:///finstack_tasks.db
   CORS_ORIGIN=http://localhost:4200,http://127.0.0.1:4200
   ```

5. **Run the application**
   ```bash
   python app.py
   ```

The API will be available at `http://localhost:5000`

## API Documentation

### Authentication Endpoints

#### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "securepassword123",
  "full_name": "John Doe"
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "johndoe",
  "password": "securepassword123"
}
```

#### Get Current User
```http
GET /api/auth/me
Authorization: Bearer <jwt-token>
```

### Task Management Endpoints

#### Create Task
```http
POST /api/tasks
Authorization: Bearer <jwt-token>
Content-Type: application/json

{
  "entity_name": "ABC Corporation",
  "task_type": "Follow-up Call",
  "task_time": "2024-12-25T10:00:00Z",
  "contact_person_id": "user-uuid-here",
  "note": "Important client meeting follow-up",
  "status": "open"
}
```

#### Get Tasks (with filtering)
```http
GET /api/tasks?status=open&task_type=meeting
Authorization: Bearer <jwt-token>
```

**Query Parameters:**
- `status`: Filter by task status (`open`, `closed`)
- `task_type`: Filter by task type (partial match)
- `entity_name`: Filter by entity name (partial match)
- `contact_person_id`: Filter by assigned user
- `date_from`: Filter tasks created after date (ISO format)
- `date_to`: Filter tasks created before date (ISO format)
- `page`: Page number (default: 1)
- `per_page`: Items per page (default: 20, max: 100)
- `sort_by`: Sort field (`date_created`, `task_time`, `entity_name`, etc.)
- `sort_order`: Sort direction (`asc`, `desc`)

#### Get Single Task
```http
GET /api/tasks/{task_id}
Authorization: Bearer <jwt-token>
```

#### Update Task
```http
PUT /api/tasks/{task_id}
Authorization: Bearer <jwt-token>
Content-Type: application/json

{
  "entity_name": "Updated Corporation",
  "task_type": "Updated Task Type",
  "status": "closed"
}
```

#### Update Task Status Only
```http
PATCH /api/tasks/{task_id}/status
Authorization: Bearer <jwt-token>
Content-Type: application/json

{
  "status": "closed"
}
```

#### Delete Task
```http
DELETE /api/tasks/{task_id}
Authorization: Bearer <jwt-token>
```

### User Management Endpoints

#### Get All Users
```http
GET /api/users
Authorization: Bearer <jwt-token>
```

### Analytics Endpoints

#### Dashboard Analytics
```http
GET /api/analytics/dashboard
Authorization: Bearer <jwt-token>
```

Returns:
```json
{
  "summary": {
    "total_tasks": 150,
    "open_tasks": 75,
    "closed_tasks": 75
  },
  "task_types": [
    {"type": "Meeting", "count": 45},
    {"type": "Follow-up", "count": 30}
  ],
  "user_tasks": [
    {"user": "John Doe", "count": 25},
    {"user": "Jane Smith", "count": 20}
  ]
}
```

### Utility Endpoints

#### Health Check
```http
GET /api/health
```

## Database Schema

### Users Table
- `id`: UUID primary key
- `username`: Unique username
- `email`: Unique email address
- `password_hash`: Hashed password
- `full_name`: User's full name
- `is_active`: Account status
- `created_at`: Account creation timestamp

### Tasks Table
- `id`: UUID primary key
- `date_created`: Task creation timestamp
- `entity_name`: Company/entity name
- `task_type`: Type of task
- `task_time`: Scheduled task time
- `contact_person_id`: Assigned user ID (foreign key)
- `note`: Optional task notes
- `status`: Task status (open/closed)
- `created_by`: Task creator ID (foreign key)
- `updated_at`: Last update timestamp

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask secret key | Generated fallback |
| `JWT_SECRET_KEY` | JWT signing key | Generated fallback |
| `DATABASE_URL` | Database connection string | SQLite local file |
| `CORS_ORIGIN` | Allowed CORS origins | localhost:4200 |

### Production Configuration

For production deployment:

1. **Set strong secret keys**
   ```bash
   SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex())')
   JWT_SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex())')
   ```

2. **Use production database**
   ```bash
   DATABASE_URL=postgresql://user:password@localhost/finstack_db
   ```

3. **Configure CORS for production domains**
   ```bash
   CORS_ORIGIN=https://yourapp.com,https://www.yourapp.com
   ```

## Security Features

- **JWT Authentication**: Secure token-based authentication
- **Password Hashing**: Werkzeug-based password security
- **Input Validation**: Marshmallow schema validation
- **CORS Protection**: Configurable cross-origin resource sharing
- **UUID Usage**: Prevents enumeration attacks
- **SQL Injection Protection**: SQLAlchemy ORM with parameterized queries

## Error Handling

The API returns structured error responses:

```json
{
  "error": "Error message",
  "details": {
    "field": ["Validation error details"]
  }
}
```

### HTTP Status Codes
- `200`: Success
- `201`: Created
- `400`: Bad Request (validation errors)
- `401`: Unauthorized
- `404`: Not Found
- `409`: Conflict (duplicate data)
- `429`: Rate Limited
- `500`: Internal Server Error

## Development

### Default Admin User
The application creates a default admin user on first run:
- **Username**: `admin`
- **Password**: `admin123`
- **Email**: `admin@finstack.com`

**⚠️ Change these credentials immediately in production!**

## Deployment

### Render Deployment

#### Requirements.txt
Ensure your `requirements.txt` includes all dependencies:
```txt
Flask==2.3.3
Flask-SQLAlchemy==3.0.5
Flask-JWT-Extended==4.5.3
Flask-CORS==4.0.0
marshmallow==3.20.1
gunicorn==21.2.0
...
```

#### Render Configuration

1. **Connect Repository**: Link your GitHub/GitLab repository to Render
2. **Service Settings**:
   - **Name**: `finstack-backend`
   - **Environment**: `Docker`
   - **Region**: Choose closest to your users
   - **Branch**: `main` or `master`
   - **Dockerfile Path**: `./Dockerfile`

3. **Environment Variables** (in Render Dashboard):
   ```
   SECRET_KEY=your-production-secret-key-here
   JWT_SECRET_KEY=your-production-jwt-secret-key-here
   DATABASE_URL=postgresql://username:password@hostname:port/database
   CORS_ORIGIN=https://your-frontend-domain.com
   FLASK_ENV=production
   ```

4. **Database Setup** (PostgreSQL on Render):
   - Create a PostgreSQL service on Render
   - Copy the connection string to `DATABASE_URL`
   - Update your code to handle PostgreSQL:
   ```python
   # Add to requirements.txt
   psycopg2-binary==2.9.7
   
   # Database URL will be automatically configured by Render
   ```

#### Deploy Steps

1. **Push to Repository**:
   ```bash
   git add .
   git commit -m "Deploy to Render"
   git push origin main
   ```

2. **Auto-Deploy**: Render will automatically build and deploy your application

3. **Health Check**: Verify deployment at `https://your-app-name.onrender.com/api/health`

#### Production Considerations

- **Database Migration**: Run migrations after deployment
- **Static Files**: Configure static file serving if needed
- **Logging**: Render automatically captures application logs
- **SSL**: HTTPS is automatically enabled on Render
- **Custom Domain**: Add your domain in Render settings

### Local Production Server
```bash
# Install production server
pip install gunicorn

# Run with Gunicorn
gunicorn --bind 0.0.0.0:5000 --workers 4 app:app
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

### Version 1.0.0
- Initial release
- User authentication and management
- Task CRUD operations
- Analytics dashboard
- RESTful API design
- Comprehensive documentation
