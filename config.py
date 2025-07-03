import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # Stripe Configuration
    STRIPE_ENV = os.getenv('STRIPE_ENV', 'test')
    STRIPE_SECRET_KEY = os.getenv('STRIPE_TEST_SECRET_KEY') if STRIPE_ENV != 'production' else os.getenv(
        'STRIPE_SECRET_KEY')
    STRIPE_API_VERSION = '2020-03-02'

    # Security Configuration
    API_KEY = os.getenv('API_KEY', 'your-api-key-change-this')

    # Rate Limiting - Simple string instead of property
    RATE_LIMIT_STORAGE_URL = os.getenv('REDIS_URL', 'memory://')

    # CORS Configuration
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', '*').split(',')

    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

    @staticmethod
    def validate_stripe_key():
        """Validate Stripe API key"""
        if not Config.STRIPE_SECRET_KEY:
            return "Error: you provided an empty secret key. Please provide your test mode secret key."

        if Config.STRIPE_SECRET_KEY.startswith('pk'):
            return "Error: you used a publishable key. Please use your test mode secret key."

        if Config.STRIPE_SECRET_KEY.startswith('sk_live'):
            return "Error: you used a live mode secret key. Please use your test mode secret key."

        return None