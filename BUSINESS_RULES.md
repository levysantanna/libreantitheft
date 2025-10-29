# LibreAntiTheft - Business Rules and Processes

## Overview

LibreAntiTheft is a secure device tracking system that allows users to monitor the location of their Android devices through OsmAnd integration. The system emphasizes security, privacy, and user control over their location data.

## Core Business Rules

### 1. User Authentication and Security

#### Password Requirements
- **Minimum Length**: 8 characters
- **Complexity**: Must contain at least one uppercase letter, one lowercase letter, and one digit
- **Storage**: Passwords are hashed using bcrypt with salt
- **Policy**: No password reuse restrictions (can be enhanced in future versions)

#### Multi-Factor Authentication (MFA)
- **Method**: Time-based One-Time Password (TOTP) using RFC 6238 standard
- **Compatibility**: Works with Google Authenticator, Authy, Microsoft Authenticator, and similar apps
- **Enforcement**: MFA is optional but strongly recommended for enhanced security
- **Recovery**: No built-in recovery mechanism (security feature)
- **Window**: 30-second time windows with 1-window tolerance for clock drift

#### Session Management
- **Access Tokens**: 30-minute lifetime (configurable)
- **Refresh Tokens**: 7-day lifetime (configurable)
- **Revocation**: Refresh tokens can be revoked and are stored in database
- **Security**: JWT tokens use HS256 algorithm with configurable secret key

### 2. Device Management

#### Device Registration
- **Ownership**: Each device belongs to exactly one user
- **Identification**: Unique device ID generated using cryptographically secure random strings
- **Authentication**: Each device has a unique secret key for OsmAnd integration
- **Naming**: Users can assign custom names to their devices
- **Status**: Devices can be activated/deactivated by their owners
- **URL Persistence**: Device URLs are automatically saved and persist across system restarts

#### Device URL Configuration
- **Automatic Creation**: Device configurations are created automatically when devices are registered
- **Default URLs**: System generates default URLs based on server configuration
- **Customization**: Users can update server URL, WebSocket URL, and API endpoint
- **Persistence**: All URL configurations are stored in the database and survive system restarts
- **Migration**: Existing devices without configurations can be migrated using the migration endpoint
- **Validation**: URL formats are validated before saving
- **Version Control**: Configuration changes are timestamped for audit purposes

#### Device Limits
- **No Hard Limit**: Users can register unlimited devices (can be restricted in future)
- **Soft Limit**: Recommended maximum of 10 devices per user for performance
- **Cleanup**: Inactive devices can be automatically archived after 90 days of no activity

### 3. Location Data Handling

#### Data Collection
- **Source**: OsmAnd Android app via HTTP POST requests
- **Frequency**: Determined by OsmAnd settings (typically every 30 seconds to 5 minutes)
- **Required Fields**: Latitude, longitude, timestamp
- **Optional Fields**: Altitude, speed, heading, accuracy, HDOP
- **Validation**: All coordinates are validated for reasonable ranges

#### Data Storage
- **Retention**: Location data is stored indefinitely (can be configured for automatic cleanup)
- **Privacy**: Location data is only accessible by the device owner
- **Encryption**: Location data is stored in plain text (can be encrypted in future versions)
- **Backup**: Regular database backups recommended

#### Data Access
- **Real-time**: WebSocket connections for live updates
- **Historical**: REST API endpoints for historical data queries
- **Export**: No built-in export functionality (can be added in future)

### 4. Security and Privacy

#### Access Control
- **Authentication**: All API endpoints require valid JWT tokens (except OsmAnd tracker endpoint)
- **Authorization**: Users can only access their own devices and location data
- **Rate Limiting**: 60 requests per minute per IP address (configurable)
- **CORS**: Configurable cross-origin resource sharing policies

#### Data Protection
- **Encryption in Transit**: HTTPS/TLS recommended for production
- **Encryption at Rest**: Database encryption recommended for production
- **Logging**: Login attempts are logged for security monitoring
- **Audit Trail**: Device actions and location updates are logged

#### Privacy Compliance
- **Data Ownership**: Users own their location data
- **Data Deletion**: Users can delete their devices and associated location data
- **No Third-Party Sharing**: Location data is never shared with third parties
- **Minimal Collection**: Only necessary location data is collected

### 5. System Architecture

#### Scalability
- **Database**: PostgreSQL for ACID compliance and reliability
- **Caching**: Redis for real-time features and session management
- **API**: FastAPI for high-performance async operations
- **WebSockets**: Real-time location updates via WebSocket connections

#### Reliability
- **Database Migrations**: Alembic for schema versioning
- **Health Checks**: Built-in health check endpoints
- **Error Handling**: Comprehensive error handling and logging
- **Monitoring**: Basic monitoring endpoints (can be enhanced)

### 6. OsmAnd Integration

#### URL Format
```
POST /osmand/tracker?lat={lat}&lon={lon}&timestamp={timestamp}&key={secret_key}
```

#### Required Parameters
- `lat`: Latitude (-90 to 90)
- `lon`: Longitude (-180 to 180)
- `timestamp`: Unix timestamp
- `key`: Device secret key

#### Optional Parameters
- `hdop`: Horizontal Dilution of Precision
- `altitude`: Altitude in meters
- `speed`: Speed in meters per second

#### Error Handling
- **Invalid Key**: 401 Unauthorized
- **Missing Parameters**: 400 Bad Request
- **Invalid Coordinates**: 400 Bad Request
- **Server Error**: 500 Internal Server Error

### 7. Dashboard and User Interface

#### Real-time Updates
- **WebSocket**: Live location updates via WebSocket connections
- **Auto-refresh**: Dashboard refreshes every 30 seconds
- **Map Integration**: OpenStreetMap integration for location visualization
- **Device Status**: Online/offline status based on last seen timestamp

#### User Experience
- **Responsive Design**: Mobile-friendly interface
- **Modern UI**: Clean, intuitive design
- **Accessibility**: Basic accessibility features
- **Performance**: Optimized for fast loading

### 8. Operational Processes

#### User Onboarding
1. User registers with username, email, and password
2. User logs in and optionally sets up MFA
3. User creates devices and notes secret keys
4. User configures OsmAnd with device URLs
5. User monitors devices via dashboard

#### Device Setup Process
1. User creates device in dashboard
2. System generates unique device ID and secret key
3. System automatically creates device configuration with default URLs
4. User can update device URLs if needed (server, WebSocket, API endpoint)
5. User configures OsmAnd with the device URLs
6. Device starts sending location data
7. User can monitor device in real-time
8. URLs persist across system restarts and updates

#### Security Incident Response
1. Monitor login attempts and failed authentications
2. Alert on suspicious activity patterns
3. Implement temporary account locks if needed
4. Review and rotate secret keys if compromised
5. Maintain audit logs for investigation

#### Data Backup and Recovery
1. Regular database backups (daily recommended)
2. Test backup restoration procedures
3. Monitor database health and performance
4. Implement disaster recovery procedures
5. Document recovery processes

### 9. Compliance and Legal

#### Data Protection
- **GDPR Compliance**: Users can request data deletion
- **Data Minimization**: Only collect necessary location data
- **Purpose Limitation**: Location data used only for tracking purposes
- **Storage Limitation**: No automatic data deletion (user-controlled)

#### Terms of Service
- Users are responsible for their device security
- Users must comply with local laws and regulations
- Service availability is not guaranteed
- Users own their data and can export/delete it

### 10. Future Enhancements

#### Planned Features
- **Geofencing**: Alert when devices enter/exit defined areas
- **Location History**: Enhanced historical data visualization
- **Data Export**: Export location data in various formats
- **Mobile App**: Native mobile application
- **API Keys**: Separate API keys for third-party integrations
- **Team Management**: Multi-user device sharing
- **Advanced Analytics**: Location pattern analysis

#### Security Enhancements
- **End-to-End Encryption**: Encrypt location data
- **Biometric Authentication**: Fingerprint/face recognition
- **Hardware Security**: TPM integration
- **Advanced Monitoring**: SIEM integration
- **Compliance**: SOC 2, ISO 27001 certification

## Conclusion

These business rules and processes ensure that LibreAntiTheft provides a secure, reliable, and user-friendly device tracking solution while maintaining the highest standards of privacy and security. The system is designed to be extensible and can be enhanced with additional features as needed.
