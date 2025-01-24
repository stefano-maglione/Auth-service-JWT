![](https://img.shields.io/badge/Spring_boot_3-blueviolet?style=for-the-badge)
![](https://img.shields.io/badge/Spring_Security_6-blueviolet?style=for-the-badge)
![](https://img.shields.io/badge/Java_17-yellow?style=for-the-badge)
![](https://img.shields.io/badge/Json_web_token-blue?style=for-the-badge)

# Auth Service Backend

Welcome to the **Auth Service Backend**, a Spring Boot-based authentication
and authorization service providing secure API endpoints for user management and authentication.

## Combined Project

This project is part of a combined solution that includes a frontend repository built with Angular.  
You can find the frontend repository
here: [Auth Service Frontend](https://github.com/stefano-maglione/Auth-frontend-JWT)

Together, these two repositories provide a complete authentication system, including user registration, login, and
secure API access.

## Architecture Overview

          +----------------------+
          |    Angular Frontend   |
          |  (Presentation Layer) |
          +----------------------+
                    |
                    v
          +----------------------+
          |  REST API Layer       |
          |  (Spring Boot)        |
          +----------------------+
                    |
          +----------------------+
          | Spring Boot Backend   |
          |  (Auth Service)       |
          +----------------------+
                    |
       +---------------------+--------------+
       |                     |              |
       v                     v              v
    +--------------+  +----------------+  +-----------------+
    |  Security    |  | Business Logic  |  |  Persistence    |
    | (JWT, CORS)  |  | (Service Layer) |  | (Database Layer)|
    +--------------+  +----------------+  +-----------------+
                                                    |
                                                    v
                                            +------------------+
                                            | H2/PostgreSQL    |
                                            | (Database)       |
                                            +------------------+

## Features

- JWT Authentication (JSON Web Token)
- Role-based Authorization (User, Admin, SuperAdmin)
- Secure Password Hashing with BCrypt
- CORS Configuration
- Stateless Authentication
- RESTful API
- H2 Database for Development

## Technologies Used

- **Spring Boot 3**
- **Spring Security**
- **JWT (JSON Web Tokens)**
- **Spring Data JPA**
- **H2 Database** (for local development)
- **Maven**

## Getting Started

### Installation

1. **Clone the Repository:**

   ```bash
   git clone git@github.com:stefano-maglione/Auth-service-JWT.git
   cd auth-service-backend
   ```

### Running with Docker Compose

1. **Build and Run the Container:**
   ```bash
   docker compose up --build
   ```


### Preloaded user:
    - email: "admin@gmail.com", password: "adminPassword"

### Testing

During the docker build unit/integration test are executed.
Results are in:

 ```bash
   docker exec -it auth-service  sh
   cd surefire-reports
   ```

or run Maven in the project:

```bash
mvn test
```

## API Endpoints available at http://localhost:8087/api/

### Public Endpoints

| Method | Endpoint                | Description                |
|--------|-------------------------|----------------------------|
| POST   | `api/user/register`     | Register a new user        |
| POST   | `api/user/authenticate` | Authenticate and get token |

#### Register

```bash
curl --location 'http://localhost:8087/api/user/register' \
--header 'Content-Type: application/json' \
--data-raw '{
"firstName": "Mark",
"lastName": "Marker",
"email": "mark@gmail.com",
"password": "markPassword"
}'
```

#### Authenticate

```bash
curl --location 'http://localhost:8087/api/user/authenticate' \
--header 'Content-Type: application/json' \
--data-raw '{
"email": "mark@gmail.com",
"password": "markPassword"
}
'
```

### Protected Endpoints

| Method | Endpoint            | Roles Allowed |
|--------|---------------------|---------------|
| GET    | `api/user/hi`       | USER          |
| GET    | `api/admin/hello`   | ADMIN         |


#### api/user/hi

```bash
curl --location 'http://localhost:8087/api/user/hi' \
--header 'Authorization: Bearer eyJhbGciOiJIUzI1N........' \
--header 'Cookie: FPID=lwKnYzp............'

```

#### api/admin/hello

```bash
curl --location 'http://localhost:8087/api/admin/hello' \
--header 'Authorization: Bearer eyJhbGciOiJIUzI1N........' \
--header 'Cookie: FPID=lwKnYzp............'

```

# Security Configuration

## Authentication Flow with JWT and Cookie fingerprint

### Authentication request

1. User credentials are sanitized to prevent XSS attacks
2. A cryptographically secure random fingerprint is generated
3. During the creation of the JWT token the fingerprint is inserted in it as claim
4. A signature is appended to the JWT token to prevent tampering.
   The signature is created by hashing the encoded header and payload.
   Symmetric HMAC with SHA-256 used with secret.
5. The fingerprint is sent as a response to the client in a cookie
   and the JWT token in the Authorization Header.(Cookie with HttpOnly, Secure flags
   only accessible by browser, not JavaScript and SameSite=Strict against CSRF attack,
   browser will only send cookies when the request is made from the same site)

### Resource request

1. User request for resource is sent with the JWT token and cookie fingerprint
2. JWT verification: extracts the signature from the token and matches it with
   the recomputed HMAC signature of the token header and payload. If they match, the token
   is considered valid.
3. The fingerprint is extracted from JWT token and matched with the one in the cookie, if
   they match the token is considered valid. Prevent session hijacking and token theft.

## Database Password

User password hashed with BCrypt

## Improvements for future versions

Secret key jwt signature to be kept securily 
(passed as env variable or a secure vault), 
https, rate limiting to prevent brute-force attacks,
token revocation, jwt expiration time to be passeed as env variable 


