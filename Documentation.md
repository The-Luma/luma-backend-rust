I'll create comprehensive documentation for the application. I'll structure it in different sections for clarity.

# Luma Backend Documentation

## Table of Contents
1. [Overview](#overview)
2. [Getting Started](#getting-started)
3. [Architecture](#architecture)
4. [API Reference](#api-reference)
5. [Authentication](#authentication)
6. [Features](#features)
7. [Configuration](#configuration)
8. [Development Guide](#development-guide)
9. [Deployment](#deployment)

## Overview

Luma Backend is a robust Rust-based backend service that provides AI-powered document management and chat functionality. The system integrates with OpenAI for intelligent conversations and Pinecone for efficient vector-based document search.

### Key Features
- AI-powered chat system
- Document management with semantic search
- User authentication and authorization
- Namespace-based organization
- PDF processing and text extraction
- Vector-based document search

## Getting Started

### Prerequisites
- Rust (latest stable version)
- PostgreSQL
- Docker (optional)
- OpenAI API key
- Pinecone API key

### Environment Setup
Create a `.env` file with the following configurations:

```env
# Server Configuration
BACKEND_PORT=8000
FRONTEND_URL=http://localhost:3000

# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/luma

# JWT Configuration
JWT_SECRET=your-secret-key
JWT_EXPIRATION=24h
REFRESH_TOKEN_EXPIRATION=7d

# OpenAI Configuration
OPENAI_API_KEY=your-openai-key
OPENAI_ORG_ID=your-org-id
OPENAI_CHAT_MODEL=gpt-4-turbo-preview

# Pinecone Configuration
PINECONE_API_KEY=your-pinecone-key
PINECONE_INDEX=your-index-name
```

### Installation

1. Clone the repository:
```bash
git clone https://github.com/your-org/luma-backend-rust.git
cd luma-backend-rust
```

2. Build the project:
```bash
cargo build --release
```

3. Run migrations:
```bash
cargo sqlx migrate run
```

4. Start the server:
```bash
cargo run --release
```

## Architecture

### Component Overview

```mermaid
graph TD
    A[Client] --> B[API Layer]
    B --> C[Authentication]
    B --> D[Chat System]
    B --> E[Document Management]
    D --> F[OpenAI Service]
    E --> G[Pinecone Service]
    E --> H[File Storage]
    B --> I[Database]
```

### Core Components

1. **API Layer** (`src/handlers/`)
   - Route handling
   - Request validation
   - Response formatting
   - Error handling

2. **Services** (`src/services/`)
   - Business logic implementation
   - External service integration
   - Data processing

3. **Models** (`src/models/`)
   - Data structures
   - Database schema
   - Request/Response types

4. **Middleware** (`src/middleware/`)
   - Authentication
   - Request processing
   - Error handling

## API Reference

### Authentication Endpoints

#### POST `/api/login`
Login with username and password.

Request:
```json
{
    "username": "string",
    "password": "string"
}
```

Response:
```json
{
    "user": {
        "id": "number",
        "username": "string",
        "email": "string",
        "role": "string"
    },
    "token": "string"
}
```

#### POST `/api/register`
Register with invitation.

Request:
```json
{
    "username": "string",
    "password": "string",
    "invitation_token": "string"
}
```

### Chat Endpoints

#### POST `/api/chat/start`
Start a new chat conversation.

Request:
```json
{
    "namespace_id": "number"
}
```

#### POST `/api/chat/message`
Send a message in a conversation.

Request:
```json
{
    "content": "string",
    "conversation_id": "number"
}
```

### Document Endpoints

#### POST `/api/documents/upload/{namespace_id}`
Upload a document to a namespace.

Request:
- Multipart form data with file

#### GET `/api/documents/{namespace_id}`
List documents in a namespace.

Response:
```json
{
    "documents": [
        {
            "id": "number",
            "name": "string",
            "created_at": "string",
            "namespace_id": "number",
            "file_metadata": "object",
            "is_public": "boolean",
            "type": "string"
        }
    ]
}
```

## Authentication

### JWT Token System

The application uses a dual-token authentication system:
1. **Access Token**: Short-lived token for API access
2. **Refresh Token**: Long-lived token for obtaining new access tokens

### Password Requirements
- Minimum 13 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

## Features

### Chat System
- Real-time messaging
- AI-powered responses
- Context-aware conversations using document knowledge
- Conversation history management
- Namespace organization

### Document Management
- File upload and storage
- PDF text extraction
- Vector embeddings for semantic search
- Access control and sharing
- Document versioning
- Namespace organization

### Vector Search
- Semantic document search
- Context retrieval for AI responses
- Efficient document chunking
- Batch processing
- Usage tracking

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| BACKEND_PORT | Server port | 8000 |
| DATABASE_URL | PostgreSQL connection URL | - |
| JWT_SECRET | Secret for JWT signing | - |
| OPENAI_API_KEY | OpenAI API key | - |
| PINECONE_API_KEY | Pinecone API key | - |

## Development Guide

### Project Structure
```
src/
├── handlers/        # API endpoint handlers
├── models/          # Data models and schemas
├── services/        # Business logic
├── middleware/      # Request middleware
├── config.rs        # Configuration management
└── main.rs         # Application entry point
```

### Adding New Features

1. **Add Models**
   - Define data structures in `models/`
   - Add database migrations if needed

2. **Implement Services**
   - Add business logic in `services/`
   - Handle external service integration

3. **Create Handlers**
   - Add route handlers in `handlers/`
   - Implement request validation
   - Handle responses and errors

### Testing

Run tests:
```bash
cargo test
```

Run with coverage:
```bash
cargo tarpaulin
```

## Deployment

### Docker Deployment

1. Build the image:
```bash
docker build -t luma-backend .
```

2. Run the container:
```bash
docker run -p 8000:8000 --env-file .env luma-backend
```

### Docker Compose

```yaml
version: '3.8'
services:
  app:
    build: .
    ports:
      - "8000:8000"
    env_file: .env
    depends_on:
      - db
  db:
    image: postgres:14
    environment:
      POSTGRES_USER: user
      POSTGRES_PASSWORD: password
      POSTGRES_DB: luma
```

### Production Considerations

1. **Security**
   - Use HTTPS
   - Set secure cookie options
   - Configure CORS properly
   - Use environment variables

2. **Performance**
   - Configure connection pools
   - Set appropriate timeouts
   - Monitor resource usage

3. **Monitoring**
   - Implement logging
   - Set up error tracking
   - Monitor API usage
   - Track external service usage

4. **Backup**
   - Regular database backups
   - Document storage backups
   - Configuration backups

This documentation provides a comprehensive overview of the Luma Backend system. Would you like me to expand on any particular section or add more specific details about any component?
