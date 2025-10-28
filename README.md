# LibreAntiTheft

A secure REST API server for OsmAnd device tracking with Multi-Factor Authentication (MFA) and real-time location dashboards.

## Features

- **Secure Authentication**: JWT-based authentication with password hashing
- **Multi-Factor Authentication**: TOTP-based MFA using authenticator apps
- **Device Management**: Register and manage multiple tracking devices
- **Real-time Tracking**: WebSocket support for live location updates
- **Web Dashboard**: Modern, responsive web interface for monitoring devices
- **OsmAnd Integration**: Compatible with OsmAnd's live tracking feature
- **Security Features**: Rate limiting, input validation, CORS protection
- **Database Support**: PostgreSQL with SQLAlchemy ORM
- **Redis Integration**: Real-time pub/sub for location updates

## Architecture

The system consists of several key components:

- **FastAPI Backend**: REST API server with WebSocket support
- **PostgreSQL Database**: Stores users, devices, and location data
- **Redis**: Handles real-time pub/sub for location updates
- **Web Dashboard**: HTML/JavaScript frontend for device monitoring
- **OsmAnd Integration**: Receives location data from Android devices

## Quick Start

### Using Docker Compose (Recommended)

1. Clone the repository:
```bash
git clone <repository-url>
cd libreantitheft
```

2. Copy the environment file:
```bash
cp env.example .env
```

3. Edit `.env` with your configuration:
```bash
# Update the secret key and other settings
nano .env
```

4. Start the services:
```bash
docker-compose up -d
```

5. Access the dashboard at `http://localhost:8000`

### Manual Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set up PostgreSQL and Redis databases

3. Configure environment variables:
```bash
cp env.example .env
# Edit .env with your database URLs and secret key
```

4. Run database migrations:
```bash
alembic upgrade head
```

5. Start the server:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## API Documentation

### Authentication Endpoints

#### Register User
```http
POST /auth/register
Content-Type: application/json

{
    "username": "johndoe",
    "email": "john@example.com",
    "password": "SecurePass123"
}
```

#### Login
```http
POST /auth/login
Content-Type: application/json

{
    "username": "johndoe",
    "password": "SecurePass123",
    "mfa_code": "123456"  // Optional if MFA is enabled
}
```

#### Refresh Token
```http
POST /auth/refresh
Content-Type: application/json

{
    "refresh_token": "your-refresh-token"
}
```

### MFA Endpoints

#### Setup MFA
```http
POST /auth/mfa/setup
Authorization: Bearer <access_token>
```

#### Verify MFA Setup
```http
POST /auth/mfa/verify
Authorization: Bearer <access_token>
Content-Type: application/json

{
    "code": "123456"
}
```

#### Disable MFA
```http
DELETE /auth/mfa/disable
Authorization: Bearer <access_token>
```

### Device Management

#### Create Device
```http
POST /devices
Authorization: Bearer <access_token>
Content-Type: application/json

{
    "name": "My Android Phone"
}
```

#### List Devices
```http
GET /devices
Authorization: Bearer <access_token>
```

#### Update Device
```http
PUT /devices/{device_id}
Authorization: Bearer <access_token>
Content-Type: application/json

{
    "name": "Updated Device Name",
    "is_active": true
}
```

#### Delete Device
```http
DELETE /devices/{device_id}
Authorization: Bearer <access_token>
```

### OsmAnd Integration

#### Receive Location Data
```http
POST /osmand/tracker?lat={lat}&lon={lon}&timestamp={timestamp}&key={secret_key}
```

Parameters:
- `lat`: Latitude (required)
- `lon`: Longitude (required)
- `timestamp`: Unix timestamp (required)
- `key`: Device secret key (required)
- `hdop`: Horizontal Dilution of Precision (optional)
- `altitude`: Altitude in meters (optional)
- `speed`: Speed in m/s (optional)

### Dashboard Endpoints

#### Get Statistics
```http
GET /dashboard/stats
Authorization: Bearer <access_token>
```

#### Get Devices with Locations
```http
GET /dashboard/devices
Authorization: Bearer <access_token>
```

## OsmAnd Configuration

To use this system with OsmAnd:

1. Create a device in the web dashboard
2. Note the device ID and secret key
3. In OsmAnd, go to Settings → Plugins → OsmAnd Live
4. Enable "Send to URL" and set the URL to:
   ```
   http://your-server.com/osmand/tracker?lat={0}&lon={1}&timestamp={2}&hdop={3}&altitude={4}&speed={5}&key=YOUR_SECRET_KEY
   ```
5. Replace `YOUR_SECRET_KEY` with the secret key from your device

## Security Features

### Password Requirements
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit

### Rate Limiting
- 60 requests per minute per IP address
- Configurable via `RATE_LIMIT_PER_MINUTE` environment variable

### MFA Security
- TOTP-based authentication using RFC 6238
- Compatible with Google Authenticator, Authy, and similar apps
- 30-second time windows with 1-window tolerance

### JWT Tokens
- Access tokens: 30 minutes (configurable)
- Refresh tokens: 7 days (configurable)
- Secure token validation and revocation

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://username:password@localhost:5432/libreantitheft` |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379/0` |
| `SECRET_KEY` | JWT secret key | `your-secret-key-here-change-this-in-production` |
| `ALGORITHM` | JWT algorithm | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Access token lifetime | `30` |
| `REFRESH_TOKEN_EXPIRE_DAYS` | Refresh token lifetime | `7` |
| `MFA_ISSUER_NAME` | MFA issuer name | `LibreAntiTheft` |
| `HOST` | Server host | `0.0.0.0` |
| `PORT` | Server port | `8000` |
| `DEBUG` | Debug mode | `True` |
| `ALLOWED_ORIGINS` | CORS allowed origins | `["http://localhost:3000", "http://localhost:8080"]` |
| `RATE_LIMIT_PER_MINUTE` | Rate limit per IP | `60` |

## Database Schema

### Users Table
- `id`: Primary key
- `username`: Unique username
- `email`: Unique email address
- `hashed_password`: Bcrypt hashed password
- `is_active`: Account status
- `is_verified`: Email verification status
- `mfa_secret`: TOTP secret key
- `mfa_enabled`: MFA status
- `created_at`: Account creation timestamp
- `updated_at`: Last update timestamp

### Devices Table
- `id`: Primary key
- `name`: Device display name
- `device_id`: Unique device identifier
- `secret_key`: Hashed secret key for authentication
- `is_active`: Device status
- `last_seen`: Last location update timestamp
- `owner_id`: Foreign key to users table
- `created_at`: Device creation timestamp

### Locations Table
- `id`: Primary key
- `latitude`: GPS latitude
- `longitude`: GPS longitude
- `altitude`: GPS altitude (optional)
- `speed`: Speed in m/s (optional)
- `heading`: Direction in degrees (optional)
- `accuracy`: GPS accuracy in meters (optional)
- `hdop`: Horizontal Dilution of Precision (optional)
- `timestamp`: Location timestamp
- `device_id`: Foreign key to devices table
- `created_at`: Record creation timestamp

## Development

### Running Tests
```bash
pytest
```

### Database Migrations
```bash
# Create a new migration
alembic revision --autogenerate -m "Description of changes"

# Apply migrations
alembic upgrade head

# Rollback migration
alembic downgrade -1
```

### Code Formatting
```bash
black app/
isort app/
```

## Production Deployment

### Security Checklist
- [ ] Change default secret key
- [ ] Use strong database passwords
- [ ] Enable HTTPS/TLS
- [ ] Configure proper CORS origins
- [ ] Set up proper firewall rules
- [ ] Enable database SSL
- [ ] Use environment-specific configurations
- [ ] Set up monitoring and logging
- [ ] Regular security updates

### Docker Production
```bash
# Build production image
docker build -t libreantitheft:latest .

# Run with production settings
docker run -d \
  --name libreantitheft \
  -p 8000:8000 \
  -e DATABASE_URL=postgresql://user:pass@db:5432/libreantitheft \
  -e REDIS_URL=redis://redis:6379/0 \
  -e SECRET_KEY=your-production-secret-key \
  -e DEBUG=False \
  libreantitheft:latest
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Support

For support and questions, please open an issue on GitHub.

## Changelog

### v1.0.0
- Initial release
- User authentication with JWT
- MFA support with TOTP
- Device management
- OsmAnd integration
- Real-time dashboard
- WebSocket support
- Security features
