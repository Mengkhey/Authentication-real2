# Authentication API Documentation

A comprehensive JWT-based authentication system with email verification, password reset, and user management.

## Base Information

- **Base URL**: `http://localhost:4000`
- **API Version**: v1
- **Authentication**: JWT Bearer Token
- **Content-Type**: `application/json`

## Quick Start

```bash
# Health check
curl http://localhost:4000/health

# Start using the API
curl -X POST http://localhost:4000/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"SecurePass123!"}'
```

## Authentication Flow

1. **Sign Up** → Email verification code sent
2. **Verify Email** → Account activated
3. **Sign In** → JWT token received
4. **Access Protected Routes** → Use JWT in Authorization header

---

## Public Endpoints

### Authentication Routes

All auth routes are rate-limited and include comprehensive validation.

#### 📝 Sign Up
```http
POST /api/auth/signup
```

Create a new user account with email verification.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "name": "John Doe" // optional
}
```

**Password Requirements:**
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

**Success Response (201):**
```json
{
  "message": "Account created successfully. Please check your email for verification code."
}
```

**Error Responses:**
```json
// Validation errors
{
  "error": "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character"
}

// Duplicate email
{
  "error": "An account with this email already exists"
}
```

---

#### ✅ Verify Email
```http
POST /api/auth/verify-email
```

Verify email address using the 6-digit code sent via email.

**Request Body:**
```json
{
  "email": "user@example.com",
  "code": "123456"
}
```

**Success Response (200):**
```json
{
  "message": "Email verified successfully! You can now sign in."
}
```

**Error Responses:**
```json
// Invalid/expired code
{
  "error": "Verification code has expired. Please request a new one."
}

// Already verified
{
  "error": "Email is already verified"
}
```

---

#### 🔑 Sign In
```http
POST /api/auth/signin
```

Authenticate user and receive JWT token.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Success Response (200):**
```json
{
  "message": "Signed in successfully",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "507f1f77bcf86cd799439011",
    "email": "user@example.com",
    "name": "John Doe",
    "emailVerified": true
  }
}
```

**Error Responses:**
```json
// Invalid credentials
{
  "error": "Invalid email or password"
}

// Email not verified
{
  "error": "Please verify your email before signing in"
}
```

---

#### 🔄 Resend Verification
```http
POST /api/auth/resend-verification
```

Resend email verification code.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Success Response (200):**
```json
{
  "message": "Verification code sent to your email"
}
```

---

#### 🔒 Forgot Password
```http
POST /api/auth/forgot-password
```

Request password reset code via email.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Success Response (200):**
```json
{
  "message": "If an account with this email exists, a password reset code has been sent."
}
```

> **Note**: For security, the response is the same whether the email exists or not.

---

#### 🆕 Reset Password
```http
POST /api/auth/reset-password
```

Reset password using verification code.

**Request Body:**
```json
{
  "email": "user@example.com",
  "code": "123456",
  "newPassword": "NewSecurePass123!"
}
```

**Success Response (200):**
```json
{
  "message": "Password has been reset successfully. Please sign in with your new password."
}
```

---

#### 🚪 Logout
```http
POST /api/auth/logout
```

Logout user (client-side token removal).

**Success Response (200):**
```json
{
  "message": "Logged out successfully"
}
```

---

## Protected Endpoints

All protected routes require JWT token in Authorization header:
```http
Authorization: Bearer your_jwt_token_here
```

### User Profile Routes

#### 👤 Get Profile
```http
GET /api/me
```

Get current user profile information.

**Success Response (200):**
```json
{
  "success": true,
  "user": {
    "id": "507f1f77bcf86cd799439011",
    "email": "user@example.com",
    "name": "John Doe",
    "fullName": "John Doe",
    "emailVerified": true,
    "profile": {
      "firstName": "John",
      "lastName": "Doe",
      "avatar": "https://example.com/avatar.jpg"
    },
    "lastLogin": "2025-09-22T10:30:00.000Z",
    "isActive": true,
    "createdAt": "2025-09-20T08:00:00.000Z",
    "updatedAt": "2025-09-22T10:30:00.000Z"
  }
}
```

---

#### ✏️ Update Profile
```http
PUT /api/me
```

Update user profile information.

**Request Body:**
```json
{
  "name": "John Smith",
  "profile": {
    "firstName": "John",
    "lastName": "Smith",
    "avatar": "https://example.com/new-avatar.jpg"
  }
}
```

**Success Response (200):**
```json
{
  "success": true,
  "message": "Profile updated successfully",
  "user": {
    // Updated user object
  }
}
```

---

#### 🗑️ Deactivate Account
```http
DELETE /api/me
```

Deactivate user account (soft delete).

**Success Response (200):**
```json
{
  "success": true,
  "message": "Account has been deactivated successfully"
}
```

---

### Account Information Routes

#### 📊 Account Statistics
```http
GET /api/account/stats
```

Get account statistics and information.

**Success Response (200):**
```json
{
  "success": true,
  "stats": {
    "accountAge": "2025-09-20T08:00:00.000Z",
    "lastLogin": "2025-09-22T10:30:00.000Z",
    "emailVerified": true,
    "profileCompleteness": 75,
    "accountStatus": "active"
  }
}
```

---

#### 🏥 System Health (Detailed)
```http
GET /api/health/detailed
```

Get detailed system health information for authenticated users.

**Success Response (200):**
```json
{
  "success": true,
  "timestamp": "2025-09-22T12:00:00.000Z",
  "uptime": 86400,
  "user": {
    "id": "507f1f77bcf86cd799439011",
    "email": "user@example.com"
  },
  "services": {
    "database": {
      "status": "ok",
      "connected": true,
      "database": "auth_db"
    },
    "email": {
      "initialized": true,
      "connected": true,
      "host": "smtp.example.com"
    }
  },
  "memory": {
    "rss": 45056000,
    "heapTotal": 20480000,
    "heapUsed": 15360000
  },
  "environment": "development"
}
```

---

## Public System Routes

#### 🏥 Health Check
```http
GET /health
```

Basic health check endpoint.

**Success Response (200):**
```json
{
  "status": "OK",
  "timestamp": "2025-09-22T12:00:00.000Z",
  "uptime": 86400
}
```

---

## Rate Limiting

Different endpoints have different rate limits:

| Endpoint Type | Limit | Window | Description |
|---------------|-------|--------|-------------|
| Strict Operations | 5 requests | 15 minutes | signup, signin, password reset |
| Verification | 3 requests | 5 minutes | email verification, resend codes |
| General Auth | 20 requests | 15 minutes | All auth routes combined |

**Rate Limit Headers:**
```http
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 4
X-RateLimit-Reset: 1695384000
```

---

## Error Handling

### Standard Error Response Format

```json
{
  "success": false,
  "error": "Error message describing what went wrong"
}
```

### Common HTTP Status Codes

| Status | Description | When it occurs |
|--------|-------------|----------------|
| `400` | Bad Request | Invalid input data, validation errors |
| `401` | Unauthorized | Invalid/missing token, authentication failed |
| `403` | Forbidden | Email not verified, account locked |
| `404` | Not Found | Resource not found, invalid endpoint |
| `409` | Conflict | Email already exists, duplicate data |
| `429` | Too Many Requests | Rate limit exceeded |
| `500` | Internal Server Error | Server-side errors |

### Validation Errors

```json
{
  "error": "Password must be at least 8 characters long"
}
```

### Authentication Errors

```json
{
  "error": "Your session has expired. Please sign in again."
}
```

---

## Development Only Endpoints

These endpoints are only available in development mode (`NODE_ENV !== 'production'`):

#### 🧪 Force Email Verification
```http
POST /api/auth/dev-verify-email
```

Instantly verify email without code (development only).

#### 🧪 Force Password Reset
```http
POST /api/auth/dev-reset-password
```

Reset password without verification code (development only).

---

## Frontend Integration

### React/JavaScript Example

```javascript
const API_BASE_URL = 'http://localhost:4000';

class AuthAPI {
  constructor() {
    this.token = localStorage.getItem('token');
  }

  // Helper method for authenticated requests
  async authenticatedRequest(url, options = {}) {
    return fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.token}`,
        ...options.headers,
      },
    });
  }

  // Authentication methods
  async signup(email, password, name) {
    const response = await fetch(`${API_BASE_URL}/api/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, name }),
    });
    return response.json();
  }

  async verifyEmail(email, code) {
    const response = await fetch(`${API_BASE_URL}/api/auth/verify-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, code }),
    });
    return response.json();
  }

  async signin(email, password) {
    const response = await fetch(`${API_BASE_URL}/api/auth/signin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    
    const data = await response.json();
    if (data.token) {
      this.token = data.token;
      localStorage.setItem('token', data.token);
    }
    return data;
  }

  async getProfile() {
    const response = await this.authenticatedRequest(`${API_BASE_URL}/api/me`);
    return response.json();
  }

  async updateProfile(updates) {
    const response = await this.authenticatedRequest(`${API_BASE_URL}/api/me`, {
      method: 'PUT',
      body: JSON.stringify(updates),
    });
    return response.json();
  }

  logout() {
    this.token = null;
    localStorage.removeItem('token');
    // Optionally call the logout endpoint
    fetch(`${API_BASE_URL}/api/auth/logout`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${this.token}` },
    });
  }
}

// Usage
const auth = new AuthAPI();

// Sign up flow
try {
  await auth.signup('user@example.com', 'SecurePass123!', 'John Doe');
  console.log('Check your email for verification code');
  
  await auth.verifyEmail('user@example.com', '123456');
  console.log('Email verified successfully');
  
  const signInResult = await auth.signin('user@example.com', 'SecurePass123!');
  console.log('Signed in:', signInResult.user);
  
  const profile = await auth.getProfile();
  console.log('Profile:', profile.user);
} catch (error) {
  console.error('Authentication error:', error);
}
```

### Error Handling Best Practices

```javascript
async function handleApiCall(apiFunction) {
  try {
    const response = await apiFunction();
    
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || 'API request failed');
    }
    
    return await response.json();
  } catch (error) {
    if (error.message.includes('session has expired')) {
      // Redirect to login page
      window.location.href = '/login';
    } else if (error.message.includes('rate limit')) {
      // Show rate limit message
      alert('Too many attempts. Please try again later.');
    } else {
      // Show generic error
      console.error('API Error:', error.message);
    }
    throw error;
  }
}
```

---

## Environment Configuration

### Required Environment Variables

```bash
# Server Configuration
PORT=4000
NODE_ENV=development

# Database
MONGO_URI=mongodb://localhost:27017/auth_db

# JWT
JWT_SECRET=your_super_secret_jwt_key_here
JWT_EXPIRES_IN=7d

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
EMAIL_FROM=noreply@yourapp.com

# Verification Codes
CODE_LENGTH=6
EMAIL_CODE_EXPIRES_MIN=15
```

### Development vs Production

**Development Features:**
- Detailed error messages with stack traces
- MongoDB debug logging
- Dev-only endpoints available
- Relaxed rate limiting
- Console logging for verification codes

**Production Features:**
- Generic error messages
- No sensitive information in responses
- Strict rate limiting
- Email service required
- Enhanced security headers

---

## Security Features

- **Password Requirements**: Strong password validation
- **Rate Limiting**: Prevents brute force attacks
- **Email Verification**: Prevents fake account creation
- **JWT Tokens**: Secure session management
- **Input Validation**: Comprehensive data validation
- **Error Handling**: No sensitive information leakage
- **Account Locking**: Protection against repeated failed attempts
- **CORS Configuration**: Controlled cross-origin access
- **Helmet.js**: Security headers
- **Bcrypt**: Secure password hashing (12 rounds)

---

## Testing the API

### Using cURL

```bash
# Health check
curl -X GET http://localhost:4000/health

# Sign up
curl -X POST http://localhost:4000/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecurePass123!","name":"Test User"}'

# Verify email (use code from email/console)
curl -X POST http://localhost:4000/api/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","code":"123456"}'

# Sign in
curl -X POST http://localhost:4000/api/auth/signin \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecurePass123!"}'

# Get profile (replace TOKEN with actual token)
curl -X GET http://localhost:4000/api/me \
  -H "Authorization: Bearer TOKEN"
```

### Using Postman/Insomnia

1. Import the API endpoints from this documentation
2. Set up environment variables for base URL and token
3. Create a collection for all auth endpoints
4. Use pre-request scripts to set authorization headers

---

## Troubleshooting

### Common Issues

**1. "Email service not initialized"**
- Check SMTP configuration in environment variables
- Verify SMTP credentials are correct
- Test email connection in development

**2. "Database connection failed"**
- Ensure MongoDB is running
- Check MONGO_URI is correct
- Verify network connectivity

**3. "Invalid token"**
- Check token format (Bearer token)
- Verify JWT_SECRET matches
- Token may have expired

**4. "Rate limit exceeded"**
- Wait for rate limit window to reset
- Check if making too many requests
- Consider implementing exponential backoff

**5. "Email not verified"**
- Check verification code in email/console
- Ensure code hasn't expired (15 minutes)
- Use resend verification endpoint

### Debug Mode

Enable debug logging by setting:
```bash
NODE_ENV=development
```

This will provide:
- Detailed error messages
- MongoDB query logging
- Verification codes in console
- Extended debugging information

---

## Changelog

### Version 1.0.0
- Complete authentication system
- Email verification
- Password reset functionality
- JWT token management
- Rate limiting
- Comprehensive error handling
- User profile management
- Account statistics
- Security enhancements