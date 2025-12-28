# 🌐 Mini-IPAM

<div align="center">

<img src="minipam.png" alt="Mini-IPAM Logo" width="200">

**A lightweight, modern IP Address Management system built for simplicity and efficiency**

[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.6-009688.svg)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Security](#-security)

</div>

---

## 📋 Overview

**Mini-IPAM** is a self-hosted IP Address Management solution designed for network administrators who need a simple, fast, and reliable way to track IP addresses, manage VLANs, and organize network resources. Built with FastAPI and a modern web interface, it provides enterprise-grade features without the complexity.

### Why Mini-IPAM?

- 🚀 **Lightweight** - Minimal dependencies, fast performance
- 🔒 **Secure** - Built-in authentication, CSRF protection, rate limiting, and audit logging
- 🎨 **Modern UI** - Clean, responsive interface built with Tailwind CSS
- 🐳 **Docker Ready** - One-command deployment with Docker Compose
- 📊 **Feature Rich** - VLAN management, IP tracking, custom icons, tags, and more
- 🔍 **Audit Trail** - Complete activity logging for compliance and troubleshooting

---

## ✨ Features

### Core Functionality

- **VLAN Management**
  - Create and manage multiple VLANs
  - CIDR subnet validation and calculation
  - Automatic gateway IP suggestions
  - Reserved IP address management

- **IP Address Tracking**
  - Assign IP addresses to devices with hostnames
  - Track device types (server, VM, container, printer, etc.)
  - Custom tags and notes for each assignment
  - Archive assignments without deletion
  - Automatic duplicate detection

- **Visual Organization**
  - Custom icon upload and management
  - Multiple icon upload support
  - Icon normalization (automatic square crop and resize)
  - Predefined icon library
  - Icon deletion and management
  - Color-coded device types
  - Visual subnet utilization

### Security & Access Control

- **Role-Based Access Control (RBAC)**
  - Admin: Full system access
  - Read/Write: Create and modify VLANs and assignments
  - Read-Only: View-only access

- **Security Features**
  - Secure password hashing (bcrypt)
  - Session-based authentication with secure cookies
  - CSRF token protection
  - Rate limiting on login attempts
  - Comprehensive audit logging

### Additional Features

- **Settings Management**
  - Customizable device type options
  - Gateway IP default behavior
  - Reserved IP defaults (network, broadcast, gateway)

- **Data Export & Import**
  - Export all data as JSON
  - Export assignments in CSV, JSON, or Excel format
  - Import assignments from CSV, JSON, or Excel files
  - Filtered exports with search and type filtering
  - Backup and restore capabilities

- **Audit Logging**
  - Complete activity trail
  - User action tracking
  - Before/after change tracking

---

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose (recommended)
- OR Python 3.12+ with pip

### Docker Deployment (Recommended)

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/minIPAM.git
   cd minIPAM
   ```

2. **Configure environment variables**
   
   Edit `docker-compose.yml` and set a secure `SECRET_KEY`:
   ```yaml
   environment:
     - SECRET_KEY=your-super-secret-key-change-this
   ```

3. **Start the application**
   ```bash
   docker-compose up -d
   ```

4. **Access the web interface**
   
   Open your browser and navigate to: `http://localhost:8080`

5. **Initial Login**
   
   On first run, an admin user is automatically created with a randomly generated password. Check the console output for the credentials:
   ```
   ============================================================
   Mini-IPAM: Initial admin user created
   ============================================================
   Username: admin
   Password: <randomly-generated-password>
   ============================================================
   Please log in and change your username and password.
   ============================================================
   ```
   
   ⚠️ **Important**: Log in immediately and change your username and password!

### Manual Installation

1. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set environment variables**
   ```bash
   export DATA_DIR=./appdata
   export SECRET_KEY=your-super-secret-key-change-this
   export COOKIE_SECURE=false  # Set to true in production with HTTPS
   ```

3. **Run the application**
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8080
   ```

4. **Access the web interface**
   
   Navigate to: `http://localhost:8080`

---

## 📖 Documentation

### User Management

#### Creating Users via CLI

Use the included CLI tool to create users:

```bash
python -m app.cli_users
```

#### User Roles

- **admin**: Full access to all features including user management and settings
- **readwrite**: Can create and modify VLANs and IP assignments
- **readonly**: View-only access to all data

### API Endpoints

The application provides a RESTful API. Key endpoints include:

- `POST /api/auth/login` - User authentication
- `GET /api/vlans` - List all VLANs
- `POST /api/vlans` - Create a new VLAN
- `GET /api/vlans/{vlan_id}` - Get VLAN details
- `POST /api/vlans/{vlan_id}/assignments` - Create IP assignment
- `GET /api/vlans/{vlan_id}/next-available` - Get next available IP
- `GET /api/vlans/{vlan_id}/assignments/export` - Export assignments (CSV/JSON/Excel)
- `POST /api/vlans/{vlan_id}/assignments/import` - Import assignments from file
- `GET /api/icons/list` - List available icons
- `POST /api/icons/upload-multiple` - Upload multiple icons (admin)
- `GET /api/audit-logs` - Get audit logs with filtering

For complete API documentation, start the server and visit:
- Swagger UI: `http://localhost:8080/docs`
- ReDoc: `http://localhost:8080/redoc`

### Data Storage

All data is stored in JSON files in the `DATA_DIR` directory:
- `data.json` - VLANs, assignments, and settings
- `users.json` - User accounts
- `audit.log` - Audit trail (append-only)

---

## 🔒 Security

### Production Deployment Checklist

- [ ] Change default admin password
- [ ] Set a strong `SECRET_KEY` (minimum 32 characters)
- [ ] Set `COOKIE_SECURE=true` when using HTTPS
- [ ] Use HTTPS/TLS in production
- [ ] Regularly backup `appdata/` directory
- [ ] Review and rotate `SECRET_KEY` periodically
- [ ] Monitor `audit.log` for suspicious activity
- [ ] Keep dependencies updated

### Security Features

- **Password Security**: Bcrypt hashing with automatic salt generation
- **Session Management**: Secure, HTTP-only cookies with configurable security
- **CSRF Protection**: Token-based protection for state-changing operations
- **Rate Limiting**: Prevents brute-force attacks on login endpoints
- **Input Validation**: Comprehensive validation on all API endpoints
- **Path Traversal Protection**: Secure file handling for icon uploads

For more security information, see [security.md](security.md).

---

## 🏗️ Architecture

### Technology Stack

- **Backend**: FastAPI (Python 3.12+)
- **Frontend**: Vanilla JavaScript with Tailwind CSS
- **Authentication**: Session-based with secure cookies
- **Storage**: JSON files (easily portable and backup-friendly)
- **Image Processing**: Pillow (PIL) for icon normalization

### Project Structure

```
minIPAM/
├── app/
│   ├── main.py          # FastAPI application and routes
│   ├── models.py        # Pydantic data models
│   ├── storage.py       # Data persistence layer
│   ├── auth.py          # Authentication and authorization
│   ├── rate_limit.py    # Rate limiting logic
│   ├── ipcalc.py        # IP/CIDR calculations
│   ├── audit.py         # Audit logging
│   ├── cli_users.py     # CLI user management
│   └── static/          # Web UI files
│       ├── index.html
│       ├── app.js
│       └── styles.css
├── icons/               # Predefined device icons
├── appdata/             # Data directory (created at runtime)
├── docker-compose.yml   # Docker Compose configuration
├── Dockerfile           # Docker image definition
└── requirements.txt     # Python dependencies
```

---

## 🛠️ Development

### Running in Development Mode

1. **Install development dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run with auto-reload**
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8080
   ```

3. **Access the application**
   - Web UI: `http://localhost:8080`
   - API Docs: `http://localhost:8080/docs`

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATA_DIR` | Directory for data storage | `/data` |
| `SECRET_KEY` | Secret key for session signing | *Required* |
| `COOKIE_SECURE` | Use secure cookies (HTTPS only) | `false` |

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/minIPAM/issues)
- **Documentation**: See the `/docs` endpoint when running the server

---

## 🙏 Acknowledgments

- Built with [FastAPI](https://fastapi.tiangolo.com/)
- UI styling with [Tailwind CSS](https://tailwindcss.com/)
- Icons and visual elements from the community

---

<div align="center">

**Made with ❤️ for network administrators**

⭐ Star this repo if you find it useful!

</div>

