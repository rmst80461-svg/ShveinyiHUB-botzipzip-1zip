# Швейный HUB - Telegram Bot for Sewing Workshop

## Overview

This is a production-ready Telegram bot for a sewing workshop ("Швейный HUB") located in Moscow. The bot handles customer orders, provides service pricing information, integrates with GigaChat AI for customer support, and includes a Flask-based admin panel for order management.

**Core functionality:**
- Order creation and tracking with photo uploads
- Service catalog with detailed pricing
- AI-powered customer support (GigaChat integration)
- 5-star review system with profanity filtering
- Anti-spam protection
- Admin dashboard with order management, user tracking, and spam logs

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Bot Framework
- **python-telegram-bot v20.7** - Async Telegram bot framework
- Uses ConversationHandler for multi-step order flows
- Inline keyboards for menu navigation
- Persistent reply keyboard with menu button

### Database Layer
- **SQLAlchemy ORM** with support for both SQLite (development) and PostgreSQL (production)
- Models: `Order`, `User`, `Review`, `SpamLog`, `Category`, `Price`, `ChatHistory`
- Database URL configured via `DATABASE_URL` environment variable
- Timezone-aware timestamps using Moscow timezone (UTC+3)

### AI Integration
- **GigaChat API** for natural language responses
- Adaptive prompts based on user context and question complexity
- Response caching to reduce API calls
- Knowledge base fallback when AI unavailable
- Character persona: "Иголочка" (needle mascot)

### Web Admin Panel
- **Flask 3.0** with Jinja2 templates
- HTTP Basic Authentication with password hashing (Werkzeug)
- CSRF protection via Flask-WTF
- Routes: dashboard, orders, users, reviews, spam logs
- CSV export functionality
- RESTful API endpoints for order status updates

### Anti-Spam System
- Rate limiting (5 messages per minute)
- Blacklist/whitelist word detection
- User muting for violations
- Spam logging for admin review

### Knowledge Base
- Text files in `data/knowledge_base/` directory
- Categories: prices, FAQ, contacts, services
- Keyword-based search for fallback responses

### Health Check
- Built-in HTTP server on port 8080 for uptime monitoring
- JSON status endpoint at `/health`

## External Dependencies

### Required Services
- **Telegram Bot API** - Bot token via `BOT_TOKEN` env var
- **GigaChat API** (Sber) - Credentials via `GIGACHAT_CREDENTIALS` env var

### Database
- SQLite for local development (default: `workshop.db`)
- PostgreSQL for production via `DATABASE_URL`

### Python Packages
- `python-telegram-bot==20.7` - Telegram integration
- `gigachat==0.1.29` - AI responses
- `sqlalchemy==2.0.23` - Database ORM
- `psycopg2-binary==2.9.9` - PostgreSQL driver
- `flask==3.0.0` - Admin web interface
- `flask-wtf` - CSRF protection
- `python-dotenv==1.0.0` - Environment configuration
- `gunicorn==22.0.0` - Production WSGI server

### Environment Variables
```
BOT_TOKEN          # Telegram bot token (required)
GIGACHAT_CREDENTIALS  # GigaChat API key
DATABASE_URL       # PostgreSQL connection string
ADMIN_ID           # Telegram user ID for admin access
ADMIN_PASSWORD     # Web admin panel password
FLASK_SECRET_KEY   # Flask session secret
```

### File Structure
- `main.py` - Bot entry point with health server
- `handlers/` - Telegram command and callback handlers
- `utils/` - Database, AI, anti-spam, caching utilities
- `webapp/` - Flask admin application
- `data/knowledge_base/` - Service information and FAQ files
- `templates/` - HTML templates for receipts