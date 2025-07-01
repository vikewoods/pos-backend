import logging
import time
from functools import wraps
from flask import request, jsonify, current_app
import stripe
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

logger = logging.getLogger(__name__)


def validate_request_data(required_fields=None, optional_fields=None):
    """Decorator to validate request data"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json and request.method == 'POST':
                return jsonify({'error': 'Content-Type must be application/json'}), 400

            data = request.get_json() if request.is_json else request.form

            if required_fields:
                missing_fields = [field for field in required_fields if field not in data]
                if missing_fields:
                    return jsonify({
                        'error': f'Missing required fields: {", ".join(missing_fields)}'
                    }), 400

            # Sanitize data
            if data:
                sanitized_data = sanitize_input(data)
                request.sanitized_data = sanitized_data

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def sanitize_input(data):
    """Sanitize input data"""
    if isinstance(data, dict):
        return {k: sanitize_input(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_input(item) for item in data]
    elif isinstance(data, str):
        # Basic sanitization - remove potentially dangerous characters
        return data.strip()[:1000]  # Limit string length
    else:
        return data


def log_security_event(event_type, details, ip_address=None):
    """Log security events"""
    logger.warning(f"SECURITY EVENT: {event_type} - {details} - IP: {ip_address or request.remote_addr}")


def validate_stripe_webhook(payload, signature):
    """Validate Stripe webhook signature"""
    endpoint_secret = current_app.config.get('STRIPE_WEBHOOK_SECRET')
    if not endpoint_secret:
        return False

    try:
        stripe.Webhook.construct_event(payload, signature, endpoint_secret)
        return True
    except Exception as e:
        log_security_event('WEBHOOK_VALIDATION_FAILED', str(e))
        return False


def generate_api_key():
    """Generate a secure API key for internal use"""
    salt = os.urandom(32)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(os.urandom(32)))
    return key.decode()


class SecurityHeaders:
    """Security headers middleware"""

    @staticmethod
    def apply_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response