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
cp .env.example .env
# Edit .env with your Stripe keys
```


3. **Run Server**
```shell script
python app.py
```


Server runs on `http://localhost:5000`

## Essential Environment Variables

```
STRIPE_TEST_SECRET_KEY=sk_test_your_key_here
STRIPE_PK_TEST_KEY=pk_test_your_key_here
SECRET_KEY=your-secure-secret-key
CORS_ORIGINS=http://localhost:3000
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
curl -X POST http://localhost:5000/create_payment_intent \
  -H "Content-Type: application/json" \
  -d '{"amount": 2000, "currency": "usd"}'

# Capture payment
curl -X POST http://localhost:5000/capture_payment_intent \
  -H "Content-Type: application/json" \
  -d '{"payment_intent_id": "pi_xxx"}'
```


## Deployment

- Set `STRIPE_ENV=live` for production
- Configure proper CORS origins
- Use Redis for rate limiting in production
- Enable HTTPS in production environment

## Security Features

- Rate limiting (200/day, 50/hour)
- Input validation and sanitization
- Security headers with Talisman
- CORS protection
- Request logging and monitoring

Ready for development and production deployment with Stripe's secure payment processing.