# Luma Backend


[Rust](https://img.shields.io/badge/rust-stable-brightgreen.svg)(https://www.rust-lang.org/)
\
[License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)(https://www.gnu.org/licenses/agpl-3.0)
\
[Docker](https://img.shields.io/badge/docker-supported-blue.svg)(https://www.docker.com/)

*A powerful, AI-driven document management and chat system built with Rust*

[Getting Started](#getting-started) •
[Documentation](#documentation) •
[Features](#features) •
[Contributing](#contributing) •
[License](#license)

</div>

##  Features

-  **AI-Powered Chat**: Intelligent conversations using OpenAI's GPT models
-  **Document Management**: Advanced document processing and organization
-  **Semantic Search**: Vector-based document search using Pinecone
-  **Secure Authentication**: JWT-based authentication with role management
-  **Namespace Organization**: Flexible content organization system
-  **PDF Processing**: Automated text extraction and analysis

##  Getting Started

### Prerequisites

- Rust (latest stable version)
- PostgreSQL 14+
- Docker (optional)
- OpenAI API key
- Pinecone API key

### Quick Start

1. **Clone the repository**
```bash
git clone https://github.com/your-org/luma-backend-rust.git
cd luma-backend-rust
```

2. **Set up environment variables**
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. **Build and run**
```bash
# Build the project
cargo build --release

# Run migrations
cargo sqlx migrate run

# Start the server
cargo run --release
```

###  Docker Setup

```bash
# Build and run with Docker
docker build -t luma-backend .
docker run -p 8000:8000 --env-file .env luma-backend

# Or using Docker Compose
docker-compose up
```

##  Documentation

Detailed documentation is available in the [docs](docs/) directory:

- [API Reference](docs/api.md)
- [Architecture Overview](docs/architecture.md)
- [Development Guide](docs/development.md)
- [Deployment Guide](docs/deployment.md)

### Basic Configuration

Create a `.env` file with the following:

```env
# Server Configuration
BACKEND_PORT=8000
FRONTEND_URL=http://localhost:3000

# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/luma

# JWT Configuration
JWT_SECRET=your-secret-key

# OpenAI Configuration
OPENAI_API_KEY=your-openai-key
OPENAI_CHAT_MODEL=gpt-4-turbo-preview

# Pinecone Configuration
PINECONE_API_KEY=your-pinecone-key
PINECONE_INDEX=your-index-name
```

##  Development

### Project Structure

```
src/
├── handlers/           # API endpoint handlers
├── models/             # Data models and schemas
├── services/           # Business logic
│   ├── auth/           # Authentication services
│   ├── chat/           # Chat services
│   └── documents/      # Document processing
├── middleware/         # Request middleware
├── config.rs           # Configuration management
└── main.rs             # Application entry point
```

### Running Tests

```bash
# Run all tests
cargo test

# Run with coverage
cargo tarpaulin

# Run specific test
cargo test test_name
```

##  Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

##  API Examples

### Authentication

```bash
# Login
curl -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user", "password": "password"}'

# Start chat
curl -X POST http://localhost:8000/api/chat/start \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"namespace_id": 1}'
```

##  Configuration Options

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| BACKEND_PORT | Server port | No | 8000 |
| DATABASE_URL | PostgreSQL URL | Yes | - |
| JWT_SECRET | JWT signing key | Yes | - |
| OPENAI_API_KEY | OpenAI API key | Yes | - |
| PINECONE_API_KEY | Pinecone API key | Yes | - |

##  License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). This means:

### What you can do:
-  Use the software for any purpose
-  Study how the software works and modify it
-  Redistribute the software
-  Make commercial use of the software
-  Distribute modified versions of the software

### What you must do:
-  Make source code available when you distribute the software
-  Include a copy of the AGPL-3.0 license with the code
-  Indicate significant changes made to the software
-  Disclose source code when running a modified version on a server

### Important Notes:
- If you modify and use this software on a network server, you MUST make the complete source code available to users who interact with the server
- All derivative works must also be licensed under AGPL-3.0
- Including this software in a larger program may require the entire program to be licensed under AGPL-3.0

For the full license text, see the [LICENSE](LICENSE) file or visit [GNU AGPL-3.0](https://www.gnu.org/licenses/agpl-3.0.en.html).

##  Deployment

### Production Checklist

-  Set secure environment variables
-  Configure HTTPS
-  Set up database backups
-  Configure logging
-  Set up monitoring
-  Review security settings

##  Status

-  Core Features
-  Authentication
-  Document Management
-  Chat System
-  Vector Search
-  Advanced Analytics (In Progress)
-  Real-time Notifications (In Progress)

---

<div align="center">


[Report Bug](https://github.com/your-org/luma-backend-rust/issues) • [Request Feature](https://github.com/your-org/luma-backend-rust/issues)

</div>
