# Stripe Payment Backend API

A secure Python Flask backend for Stripe payment processing with Terminal support. This API provides endpoints for payment processing, terminal management, and secure payment handling.

## Features

- **Payment Processing**: Create, capture, and cancel payment intents
- **Terminal Support**: Register and manage Stripe Terminal readers
- **Security**: Rate limiting, CORS protection, input validation
- **Setup Intents**: Support for saving payment methods
- **Location Management**: Create and list terminal locations

## Quick Setup

1. **Install Dependencies**
```shell script
pip install -r requirements.txt
```


2. **Environment Configuration**
```shell script
cp .env.example .env.production
# Edit .env.production with your Stripe keys for Live
# Edit .env with your Stripe keys for Test
```


3. **Run Server**
```shell script
python app.py
```




Server runs on `http://localhost:8247`

## Essential Environment Variables

```
STRIPE_ENV=test
STRIPE_TEST_SECRET_KEY=sk_test_
STRIPE_PK_TEST_KEY=pk_test_
STRIPE_SECRET_KEY=sk_live_
STRIPE_WEBHOOK_SECRET=whsec_

API_KEY= #python -c "import secrets; print('API_KEY=' + secrets.token_urlsafe(32))"
CORS_ORIGINS=http://localhost:3000,http://localhost:5000,https://pos-terminal.example.co.uk

FLASK_ENV=production
APP_PORT=8247

REDIS_URL=redis://redis:6379

DOMAIN_NAME=pos-terminal.example.co.uk
RATE_LIMIT_PER_SECOND=10
RATE_LIMIT_BURST=20
```


## Key Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/connection_token` | POST | Terminal connection token |
| `/create_payment_intent` | POST | Create payment intent |
| `/capture_payment_intent` | POST | Capture payment |
| `/register_reader` | POST | Register terminal reader |
| `/list_locations` | GET | List terminal locations |
| `/check_terminal_status` | GET/POST | Check reader status |

## Quick Payment Example

```shell script
# Create payment intent
curl -X POST http://localhost:8247/create_payment_intent \
  -H "X-API-Key: your-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{"amount": 2000, "currency": "gbp"}'

# Capture payment
curl -X POST http://localhost:8247/capture_payment_intent \
  -H "X-API-Key: your-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{"payment_intent_id": "pi_xxx"}'
```


## Deployment

- Set `STRIPE_ENV=live` for production
- Set `FLASK_ENV=production`
- Configure proper CORS origins
- Use Redis for rate limiting in production
- Enable HTTPS in production environment
- Use basic API key implementation in headers `"X-API-Key: your-api-key-here"`

## Docker deployment
- Docker and Docker Compose installed
- SSL certificates (for production)
- Environment variables configured

### Environment Setup

1. **Copy the environment template:**
```shell script
cp .env.example .env.production
```

2. **Generate a secure API key:**
```shell script
python -c "import secrets; print('API_KEY=' + secrets.token_urlsafe(32))"
```

3. **Configure your .env.production file:**
```dotenv
   # Stripe Configuration (using test environment for production)
   STRIPE_ENV=live
   STRIPE_TEST_SECRET_KEY=sk_live_
   STRIPE_PK_TEST_KEY=pk_live_
   STRIPE_SECRET_KEY=sk_live_
   STRIPE_WEBHOOK_SECRET=whsec_

   # Application Security
   API_KEY=your-generated-secure-api-key-here
   CORS_ORIGINS=https://your-main-domain.com

   # Domain and Infrastructure
   DOMAIN_NAME=pos-terminal.your-main-domain.com
   FLASK_ENV=production
   APP_PORT=8247
   REDIS_URL=redis://redis:6379

   # Rate Limiting
   RATE_LIMIT_PER_SECOND=10
   RATE_LIMIT_BURST=20

   # Logging
   LOG_LEVEL=INFO
```

4. **Prepare SSLs:**
```shell script
mkdir -p ssl/
# Copy your SSL certificate files:
# ssl/cert.pem - Your SSL certificate
# ssl/key.pem - Your private key
```

5. **Deploy with production configuration:**
```shell script
docker-compose -f docker-compose.prod.yml up -d --build
```

6. **Monitor the deployment:**
```shell script
docker-compose -f docker-compose.prod.yml ps
docker-compose -f docker-compose.prod.yml logs -f
```


### Container Management
**View running containers:**
``` bash
docker-compose -f docker-compose.prod.yml ps
```
**View application logs:**
``` bash
docker-compose -f docker-compose.prod.yml logs stripe-backend
```
**View nginx logs:**
``` bash
docker-compose -f docker-compose.prod.yml logs nginx
```
**Restart a specific service:**
``` bash
docker-compose -f docker-compose.prod.yml restart stripe-backend
```
**Update and rebuild:**
``` bash
docker-compose -f docker-compose.prod.yml down
docker-compose -f docker-compose.prod.yml up -d --build
```

**Backup data:**
``` bash
# Backup Redis data
docker-compose -f docker-compose.prod.yml exec redis redis-cli BGSAVE

# Backup logs
tar -czf logs-backup-$(date +%Y%m%d).tar.gz logs/
```
**Update containers:**
``` bash
# Pull latest images
docker-compose -f docker-compose.prod.yml pull

# Restart with new images
docker-compose -f docker-compose.prod.yml up -d
```
**Clean up:**
``` bash
# Remove unused containers and images
docker system prune -f

# Remove unused volumes (careful!)
docker volume prune -f
```

## Security Features

- Rate limiting (200/day, 50/hour)
- Input validation and sanitization
- Security headers with Talisman
- CORS protection
- Request logging and monitoring

Ready for development and production deployment with Stripe's secure payment processing.