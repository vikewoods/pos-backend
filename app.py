from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import stripe
import logging
import json
from datetime import datetime, timedelta
import os

from config import Config
from security import validate_request_data, log_security_event, SecurityHeaders

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Configure logging
logging.basicConfig(
    level=getattr(logging, app.config['LOG_LEVEL']),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize extensions
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=app.config['RATE_LIMIT_STORAGE_URL'],
    default_limits=["200 per day", "50 per hour"]
)

# Configure CORS with security
CORS(app, origins=app.config['CORS_ORIGINS'], supports_credentials=True)

# Security headers
Talisman(app, force_https=False)  # Set to True in production

# Configure Stripe
stripe.api_key = app.config['STRIPE_SECRET_KEY']
stripe.api_version = app.config['STRIPE_API_VERSION']


def log_info(message):
    """Log information and return message"""
    logger.info(message)
    return message


def validate_api_key():
    """Validate Stripe API key"""
    return Config.validate_stripe_key()


def handle_stripe_error(e):
    """Handle Stripe errors consistently"""
    error_msg = f"Stripe error: {str(e)}"
    log_security_event('STRIPE_ERROR', error_msg)
    logger.error(error_msg)
    return jsonify({'error': error_msg}), 402


# Apply security headers to all responses
@app.after_request
def after_request(response):
    return SecurityHeaders.apply_headers(response)


# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})


@app.route('/', methods=['GET'])
def index():
    """Serve index.html"""
    try:
        return send_file('index.html')
    except FileNotFoundError:
        return jsonify({'error': 'Index file not found'}), 404


@app.route('/register_reader', methods=['POST'])
@limiter.limit("10 per minute")
@validate_request_data(required_fields=['registration_code', 'label', 'location'])
def register_reader():
    """Register a Verifone P400 reader"""
    validation_error = validate_api_key()
    if validation_error:
        return jsonify({'error': validation_error}), 400

    data = request.sanitized_data

    try:
        reader = stripe.terminal.Reader.create(
            registration_code=data['registration_code'],
            label=data['label'],
            location=data['location']
        )

        log_info(f"Reader registered: {reader.id}")
        return jsonify({
            'id': reader.id,
            'label': reader.label,
            'location': reader.location,
            'status': reader.status
        })

    except stripe.error.StripeError as e:
        return handle_stripe_error(e)


@app.route('/connection_token', methods=['POST'])
@limiter.limit("30 per minute")
def connection_token():
    """Create a connection token"""
    validation_error = validate_api_key()
    if validation_error:
        return jsonify({'error': validation_error}), 400

    try:
        token = stripe.terminal.ConnectionToken.create()
        return jsonify({'secret': token.secret})

    except stripe.error.StripeError as e:
        return handle_stripe_error(e)


@app.route('/create_payment_intent', methods=['POST'])
@limiter.limit("20 per minute")
@validate_request_data(required_fields=['amount'])
def create_payment_intent():
    """Create a PaymentIntent"""
    validation_error = validate_api_key()
    if validation_error:
        return jsonify({'error': validation_error}), 400

    data = request.sanitized_data

    # Validate amount
    try:
        amount = int(data['amount'])
        if amount <= 0 or amount > 999999999:  # Max amount validation
            return jsonify({'error': 'Invalid amount'}), 400
    except (ValueError, TypeError):
        return jsonify({'error': 'Amount must be a valid integer'}), 400

    try:
        payment_intent = stripe.PaymentIntent.create(
            payment_method_types=data.get('payment_method_types', ['card_present']),
            capture_method=data.get('capture_method', 'manual'),
            amount=amount,
            currency=data.get('currency', 'gbp'),
            description=data.get('description', 'Example PaymentIntent')[:500],  # Limit description
            receipt_email=data.get('receipt_email'),
        )

        log_info(f"PaymentIntent created: {payment_intent.id}")
        return jsonify({
            'intent': payment_intent.id,
            'secret': payment_intent.client_secret
        })

    except stripe.error.StripeError as e:
        return handle_stripe_error(e)


@app.route('/capture_payment_intent', methods=['POST'])
@limiter.limit("20 per minute")
@validate_request_data(required_fields=['payment_intent_id'])
def capture_payment_intent():
    """Capture a PaymentIntent"""
    data = request.sanitized_data
    payment_intent_id = data['payment_intent_id']

    try:
        # Validate payment intent ID format
        if not payment_intent_id.startswith('pi_'):
            return jsonify({'error': 'Invalid payment intent ID format'}), 400

        capture_params = {}
        if data.get('amount_to_capture'):
            capture_params['amount_to_capture'] = int(data['amount_to_capture'])

        payment_intent = stripe.PaymentIntent.capture(payment_intent_id, **capture_params)

        log_info(f"PaymentIntent captured: {payment_intent_id}")
        return jsonify({
            'intent': payment_intent.id,
            'secret': payment_intent.client_secret
        })

    except stripe.error.StripeError as e:
        return handle_stripe_error(e)
    except ValueError:
        return jsonify({'error': 'Invalid amount_to_capture'}), 400


@app.route('/cancel_payment_intent', methods=['POST'])
@limiter.limit("20 per minute")
@validate_request_data(required_fields=['payment_intent_id'])
def cancel_payment_intent():
    """Cancel a PaymentIntent"""
    data = request.sanitized_data
    payment_intent_id = data['payment_intent_id']

    try:
        # Validate payment intent ID format
        if not payment_intent_id.startswith('pi_'):
            return jsonify({'error': 'Invalid payment intent ID format'}), 400

        payment_intent = stripe.PaymentIntent.cancel(payment_intent_id)

        log_info(f"PaymentIntent canceled: {payment_intent_id}")
        return jsonify({
            'intent': payment_intent.id,
            'secret': payment_intent.client_secret
        })

    except stripe.error.StripeError as e:
        return handle_stripe_error(e)


@app.route('/create_setup_intent', methods=['POST'])
@limiter.limit("20 per minute")
def create_setup_intent():
    """Create a SetupIntent"""
    validation_error = validate_api_key()
    if validation_error:
        return jsonify({'error': validation_error}), 400

    data = request.get_json() or {}

    try:
        setup_intent_params = {
            'payment_method_types': data.get('payment_method_types', ['card_present'])
        }

        # Optional parameters
        if data.get('customer'):
            setup_intent_params['customer'] = data['customer']
        if data.get('description'):
            setup_intent_params['description'] = data['description'][:500]  # Limit description
        if data.get('on_behalf_of'):
            setup_intent_params['on_behalf_of'] = data['on_behalf_of']

        setup_intent = stripe.SetupIntent.create(**setup_intent_params)

        log_info(f"SetupIntent created: {setup_intent.id}")
        return jsonify({
            'intent': setup_intent.id,
            'secret': setup_intent.client_secret
        })

    except stripe.error.StripeError as e:
        return handle_stripe_error(e)


def lookup_or_create_example_customer():
    """Look up or create example customer"""
    customer_email = "example@test.com"

    try:
        customers = stripe.Customer.list(email=customer_email, limit=1)
        if customers.data:
            return customers.data[0]
        else:
            return stripe.Customer.create(email=customer_email)
    except stripe.error.StripeError as e:
        raise e


@app.route('/attach_payment_method_to_customer', methods=['POST'])
@limiter.limit("10 per minute")
@validate_request_data(required_fields=['payment_method_id'])
def attach_payment_method_to_customer():
    """Attach PaymentMethod to Customer"""
    data = request.sanitized_data
    payment_method_id = data['payment_method_id']

    try:
        # Validate payment method ID format
        if not payment_method_id.startswith('pm_'):
            return jsonify({'error': 'Invalid payment method ID format'}), 400

        customer = lookup_or_create_example_customer()

        payment_method = stripe.PaymentMethod.attach(
            payment_method_id,
            customer=customer.id
        )

        log_info(f"PaymentMethod attached to customer: {customer.id}")
        return jsonify({
            'id': payment_method.id,
            'customer': payment_method.customer,
            'type': payment_method.type
        })

    except stripe.error.StripeError as e:
        return handle_stripe_error(e)


@app.route('/update_payment_intent', methods=['POST'])
@limiter.limit("20 per minute")
@validate_request_data(required_fields=['payment_intent_id'])
def update_payment_intent():
    """Update PaymentIntent"""
    data = request.sanitized_data
    payment_intent_id = data['payment_intent_id']

    try:
        # Validate payment intent ID format
        if not payment_intent_id.startswith('pi_'):
            return jsonify({'error': 'Invalid payment intent ID format'}), 400

        # Only allow specific fields to be updated
        allowed_keys = ['receipt_email']
        update_params = {k: v for k, v in data.items() if k in allowed_keys}

        if not update_params:
            return jsonify({'error': 'No valid fields to update'}), 400

        payment_intent = stripe.PaymentIntent.modify(payment_intent_id, **update_params)

        log_info(f"PaymentIntent updated: {payment_intent_id}")
        return jsonify({
            'intent': payment_intent.id,
            'secret': payment_intent.client_secret
        })

    except stripe.error.StripeError as e:
        return handle_stripe_error(e)


@app.route('/list_locations', methods=['GET'])
@limiter.limit("10 per minute")
def list_locations():
    """List Terminal locations"""
    validation_error = validate_api_key()
    if validation_error:
        return jsonify({'error': validation_error}), 400

    try:
        locations = stripe.terminal.Location.list(limit=100)

        log_info(f"{len(locations.data)} locations fetched")
        return jsonify([{
            'id': loc.id,
            'display_name': loc.display_name,
            'address': loc.address
        } for loc in locations.data])

    except stripe.error.StripeError as e:
        return handle_stripe_error(e)


@app.route('/create_location', methods=['POST'])
@limiter.limit("5 per minute")
@validate_request_data(required_fields=['display_name', 'address'])
def create_location():
    """Create a Terminal location"""
    validation_error = validate_api_key()
    if validation_error:
        return jsonify({'error': validation_error}), 400

    data = request.sanitized_data

    try:
        location = stripe.terminal.Location.create(
            display_name=data['display_name'][:100],  # Limit length
            address=data['address']
        )

        log_info(f"Location created: {location.id}")
        return jsonify({
            'id': location.id,
            'display_name': location.display_name,
            'address': location.address
        })

    except stripe.error.StripeError as e:
        return handle_stripe_error(e)


# Add this new endpoint after your existing routes

@app.route('/check_terminal_status', methods=['GET', 'POST'])
@limiter.limit("30 per minute")
def check_terminal_status():
    """Check the status of a Terminal reader"""
    validation_error = validate_api_key()
    if validation_error:
        return jsonify({'error': validation_error}), 400

    # Get reader ID from request (either query param or JSON body)
    if request.method == 'GET':
        reader_id = request.args.get('reader_id')
    else:  # POST
        data = request.get_json() or {}
        reader_id = data.get('reader_id')

    if not reader_id:
        return jsonify({'error': 'reader_id is required'}), 400

    try:
        # Validate reader ID format
        if not reader_id.startswith('tmr_'):
            return jsonify({'error': 'Invalid reader ID format. Should start with "tmr_"'}), 400

        # Retrieve the reader from Stripe
        reader = stripe.terminal.Reader.retrieve(reader_id)

        log_info(f"Terminal status checked for reader: {reader_id}")

        # Return comprehensive status information
        return jsonify({
            'reader_id': reader.id,
            'label': reader.label,
            'status': reader.status,
            'device_type': reader.device_type,
            'serial_number': reader.serial_number,
            'location': reader.location,
            'ip_address': reader.ip_address,
            'device_sw_version': reader.device_sw_version,
            'registration_status': {
                'is_registered': reader.status in ['online', 'offline'],
                'is_online': reader.status == 'online',
                'is_offline': reader.status == 'offline'
            },
            'last_seen_at': reader.last_seen_at,
            'metadata': reader.metadata
        })

    except stripe.error.InvalidRequestError as e:
        # Reader not found or invalid ID
        error_msg = f"Reader not found: {str(e)}"
        log_security_event('TERMINAL_CHECK_FAILED', error_msg)
        return jsonify({'error': 'Reader not found or invalid reader ID'}), 404

    except stripe.error.StripeError as e:
        return handle_stripe_error(e)


@app.route('/list_readers', methods=['GET'])
@limiter.limit("10 per minute")
def list_readers():
    """List all Terminal readers (helpful for getting reader IDs)"""
    validation_error = validate_api_key()
    if validation_error:
        return jsonify({'error': validation_error}), 400

    try:
        # Get optional location filter
        location_id = request.args.get('location')

        list_params = {'limit': 100}
        if location_id:
            list_params['location'] = location_id

        readers = stripe.terminal.Reader.list(**list_params)

        log_info(f"{len(readers.data)} readers fetched")

        return jsonify([{
            'id': reader.id,
            'label': reader.label,
            'status': reader.status,
            'device_type': reader.device_type,
            'location': reader.location,
            'serial_number': reader.serial_number,
            'ip_address': reader.ip_address,
            'last_seen_at': reader.last_seen_at,
            'is_online': reader.status == 'online'
        } for reader in readers.data])

    except stripe.error.StripeError as e:
        return handle_stripe_error(e)

# Error handlers
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded'}), 429


@app.errorhandler(404)
def not_found_handler(e):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error_handler(e):
    logger.error(f"Internal server error: {str(e)}")
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    port = int(os.environ.get('APP_PORT', 8247))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_ENV') == 'development')
