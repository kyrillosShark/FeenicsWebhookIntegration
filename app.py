import os
import sys
import json
import uuid
import random
import base64
import logging
import threading
import datetime
from datetime import timezone, timedelta
import time
import phonenumbers
from phonenumbers import NumberParseException
from flask import Flask, request, jsonify, abort, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from twilio.rest import Client
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import geopy

from bson import BSON  # From pymongo
from dotenv import load_dotenv

load_dotenv()

# ----------------------------
# Configuration and Setup
# ----------------------------

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)
app.config['DEBUG'] = True

# Environment Variables
BASE_ADDRESS = os.getenv("BASE_ADDRESS")
INSTANCE_NAME = os.getenv("INSTANCE_NAME")
KEEP_USERNAME = os.getenv("KEEP_USERNAME")
KEEP_PASSWORD = os.getenv("KEEP_PASSWORD")
BADGE_TYPE_NAME = os.getenv("BADGE_TYPE_NAME", "Employee Badge")
SIMULATION_REASON = os.getenv("SIMULATION_REASON", "Automated Testing of Card Read")
FACILITY_CODE = int(os.getenv("FACILITY_CODE", 111))  # Set your facility code here
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")
UNLOCK_LINK_BASE_URL = os.getenv("UNLOCK_LINK_BASE_URL")
DATABASE_URL = os.getenv("DATABASE_URL")

# Check for required environment variables
required_env_vars = [
    'BASE_ADDRESS', 'INSTANCE_NAME', 'KEEP_USERNAME', 'KEEP_PASSWORD',
    'TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN', 'TWILIO_PHONE_NUMBER',
    'UNLOCK_LINK_BASE_URL', 'DATABASE_URL'
]

loaded_vars = {
    'BASE_ADDRESS': BASE_ADDRESS,
    'INSTANCE_NAME': INSTANCE_NAME,
    'KEEP_USERNAME': KEEP_USERNAME,
    'KEEP_PASSWORD': KEEP_PASSWORD,
    'TWILIO_ACCOUNT_SID': TWILIO_ACCOUNT_SID,
    'TWILIO_AUTH_TOKEN': TWILIO_AUTH_TOKEN,
    'TWILIO_PHONE_NUMBER': TWILIO_PHONE_NUMBER,
    'UNLOCK_LINK_BASE_URL': UNLOCK_LINK_BASE_URL,
    'DATABASE_URL': DATABASE_URL
}

missing_env_vars = [var for var, value in loaded_vars.items() if not value]
if missing_env_vars:
    logger.error(f"Missing environment variables: {', '.join(missing_env_vars)}")
    sys.exit(1)

# Database Configuration using DATABASE_URL
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Initialize Twilio Client
client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# Session with Retry Strategy
def create_session():
    session = requests.Session()
    retry = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    return session

SESSION = create_session()

def validate_phone_number(number):
    try:
        parsed_number = phonenumbers.parse(number, None)
        return phonenumbers.is_possible_number(parsed_number) and phonenumbers.is_valid_number(parsed_number)
    except NumberParseException:
        return False

# ----------------------------
# Database Models
# ----------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=False, nullable=False)
    phone_number = db.Column(db.String(20), unique=False, nullable=False)
    facility_code = db.Column(db.Integer, nullable=False)
    card_number = db.Column(db.Integer, unique=True, nullable=False)  # Raw 16-bit Card Number
    formatted_card_number = db.Column(db.String(20), unique=True, nullable=False)  # 26-bit Formatted Card Number
    membership_start = db.Column(db.DateTime, nullable=False)
    membership_end = db.Column(db.DateTime, nullable=False)
    external_id = db.Column(db.String(50), unique=True, nullable=False)

    def is_membership_active(self):
        now = datetime.datetime.utcnow()
        return self.membership_start <= now <= self.membership_end

class UnlockToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(36), unique=False, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    external_id = db.Column(db.String(50), unique=False, nullable=False)

    user = db.relationship('User', backref=db.backref('unlock_tokens', lazy=True))

    def is_valid(self):
        now = datetime.datetime.utcnow()
        return not self.used and now < self.expires_at and self.user.is_membership_active()

# ----------------------------
# Helper Functions
# ----------------------------

def get_access_token(base_address, instance_name, username, password):
    """
    Authenticates with the Keep by Feenics API and retrieves an access token.

    Returns:
        tuple: (access_token, instance_id)
    """
    token_endpoint = f"{base_address}/token"

    payload = {
        "grant_type": "password",
        "client_id": "consoleApp",
        "client_secret": "consoleSecret",
        "username": username,
        "password": password,
        "instance": instance_name,
        "sendonetimepassword": "false",
        "undefined": ""
    }

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    body_encoded = "&".join([f"{key}={value}" for key, value in payload.items()])

    try:
        response = SESSION.post(token_endpoint, headers=headers, data=body_encoded)
        response.raise_for_status()

        response_data = response.json()
        access_token = response_data.get("access_token")
        instance_id = response_data.get("instance")

        if not access_token or not instance_id:
            raise Exception("Access token or instance ID not found in the response.")

        logger.info("CRM login successful.")
        return access_token, instance_id
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error during CRM login: {http_err}")
        logger.error(f"Response Content: {response.text}")
        raise
    except Exception as err:
        logger.error(f"Error during CRM login: {err}")
        raise

def get_badge_types(base_address, access_token, instance_id):
    """
    Retrieves a list of available Badge Types.
    """
    get_badge_types_endpoint = f"{base_address}/api/f/{instance_id}/badgetypes"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        response = SESSION.get(get_badge_types_endpoint, headers=headers)
        response.raise_for_status()

        badge_types_data = response.json()

        if isinstance(badge_types_data, dict) and 'value' in badge_types_data:
            badge_types = badge_types_data['value']
        elif isinstance(badge_types_data, list):
            badge_types = badge_types_data
        else:
            badge_types = []
            logger.warning("Unexpected format for badge_types_data.")

        logger.info(f"Retrieved {len(badge_types)} badge types.")
        return badge_types
    except Exception as err:
        logger.error(f"Error retrieving badge types: {err}")
        raise

def create_badge_type(base_address, access_token, instance_id, badge_type_name):
    """
    Creates a new Badge Type in the Keep by Feenics system.

    Returns:
        dict: Details of the created Badge Type.
    """
    create_badge_endpoint = f"{base_address}/api/f/{instance_id}/badgetypes"

    badge_type_data = {
        "CommonName": badge_type_name,
        "Description": f"{badge_type_name} Description"
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        response = SESSION.post(create_badge_endpoint, headers=headers, json=badge_type_data)
        response.raise_for_status()

        response_data = response.json()
        badge_type_id = response_data.get("Key")

        if not badge_type_id:
            raise Exception("Badge Type ID not found in the response.")

        logger.info(f"Badge Type '{badge_type_name}' created successfully with ID: {badge_type_id}")
        return response_data
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 409:
            logger.info(f"Badge Type '{badge_type_name}' already exists.")
            return None
        else:
            logger.error(f"HTTP error during Badge Type creation: {http_err}")
            logger.error(f"Response Content: {response.text}")
            raise
    except Exception as err:
        logger.error(f"Error during Badge Type creation: {err}")
        raise

def get_badge_type_details(base_address, access_token, instance_id, badge_type_name):
    """
    Retrieves details of a specific Badge Type.
    """
    badge_types = get_badge_types(base_address, access_token, instance_id)

    for bt in badge_types:
        if bt.get("CommonName") == badge_type_name:
            return bt

    raise Exception(f"Badge Type '{badge_type_name}' not found after creation.")

def format_hid_26bit_h10301(facility_code, card_number):
    """
    Formats card credentials according to HID 26-bit H10301 format specifications.
    Standard 26 Bit Format: 1 even parity bit + 8 facility bits + 16 card number bits + 1 odd parity bit
    """
    # Validate facility code range (8 bits)
    if not 0 <= facility_code <= 255:
        return None, "Facility code must be between 0 and 255"

    # Validate card number range (16 bits)
    if not 0 <= card_number <= 65535:
        return None, "Card number must be between 0 and 65535"

    # Convert to binary strings, padding to required length
    facility_bits = format(facility_code, '08b')
    card_bits = format(card_number, '016b')

    # Combine into 24-bit string (excluding parity bits for now)
    combined_bits = facility_bits + card_bits  # 24 bits

    # Calculate even parity (left) for first 12 bits
    first_12_bits = combined_bits[:12]
    even_parity_bit = str(sum(int(bit) for bit in first_12_bits) % 2)

    # Calculate odd parity (right) for last 12 bits
    last_12_bits = combined_bits[12:]
    odd_parity_bit = str((sum(int(bit) for bit in last_12_bits) + 1) % 2)

    # Assemble final 26-bit format
    final_bits = even_parity_bit + combined_bits + odd_parity_bit  # 26 bits

    # Ensure final_bits is exactly 26 bits
    assert len(final_bits) == 26, f"Final bits length is {len(final_bits)}, expected 26."

    # Convert binary to decimal
    decimal_value = int(final_bits, 2)
    formatted_number = str(decimal_value)

    logger.debug(f"Formatted Number: {formatted_number} (Binary: {final_bits})")

    return formatted_number, None

def generate_card_number() -> int:
    """
    Generates a random card number using facility code from environment variable.
    Returns:
        int: card_number
    Raises:
        ValueError: If FACILITY_CODE environment variable is missing or invalid
    """
    try:
        facility_code = int(os.environ['FACILITY_CODE'])
        if not 0 <= facility_code <= 255:
            raise ValueError("FACILITY_CODE must be between 0 and 255")
    except KeyError:
        raise ValueError("FACILITY_CODE environment variable is not set")
    except ValueError as e:
        if str(e).startswith("FACILITY_CODE must be"):
            raise
        raise ValueError("FACILITY_CODE environment variable must be a valid integer")

    # Generate 16-bit card number
    card_number = random.randint(0, 65535)
    logger.debug(f"Generated card_number: {card_number}")
    return card_number

def get_access_levels(base_address, access_token, instance_id):
    access_levels_endpoint = f"{base_address}/api/f/{instance_id}/accesslevels"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        response = SESSION.get(access_levels_endpoint, headers=headers)
        response.raise_for_status()
        access_levels_data = response.json()

        # Handle both list and dict responses
        if isinstance(access_levels_data, dict):
            access_levels = access_levels_data.get('value', [])
            if not access_levels:
                logger.warning("No access levels found under 'value' key.")
        elif isinstance(access_levels_data, list):
            access_levels = access_levels_data
        else:
            logger.error("Unexpected data format for access levels.")
            access_levels = []

        logger.info(f"Retrieved {len(access_levels)} access levels.")

        # Log each access level's Key and Href
        for al in access_levels:
            logger.debug(f"Access Level: Key={al.get('Key')}, Href={al.get('Href')}, CommonName={al.get('CommonName')}")

        return access_levels
    except Exception as err:
        logger.error(f"Error retrieving access levels: {err}")
        raise

def create_user(base_address, access_token, instance_id, first_name, last_name, email, phone_number, badge_type_info, membership_duration_hours, external_id):
    """
    Creates a new user in the Keep by Feenics system.

    Returns:
        tuple: (User object, user_id)
    """
    create_person_endpoint = f"{base_address}/api/f/{instance_id}/people"

    # ----------------------------
    # Step 1: Generate and Format Card Number
    # ----------------------------

    # Generate raw 16-bit card number
    card_number = generate_card_number()  # Returns int within 0-65535
    facility_code = FACILITY_CODE  # From environment variable
    logger.debug(f"Generated Card Number: {card_number}, Facility Code: {facility_code}")

    # Format the card number into a 26-bit number
    formatted_card_number, error_message = format_hid_26bit_h10301(facility_code, card_number)

    if formatted_card_number is None:
        logger.error(f"Error formatting card number: {error_message}")
        raise ValueError(error_message)

    logger.debug(f"Formatted Card Number (26-bit): {formatted_card_number}")

    # ----------------------------
    # Step 2: Prepare Active and Expiration Times
    # ----------------------------

    active_on = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    expires_on = (datetime.datetime.utcnow() + timedelta(hours=membership_duration_hours)).replace(microsecond=0).isoformat() + "Z"

    # ----------------------------
    # Step 3: Retrieve Card Formats
    # ----------------------------

    card_formats = get_card_formats(base_address, access_token, instance_id)
    if not card_formats:
        logger.error("No card formats found.")
        raise Exception("No card formats available to assign to the card.")

    # Use the first available card format
    selected_card_format = card_formats[0]
    logger.info(f"Using card format: {selected_card_format.get('CommonName')}")

    # ----------------------------
    # Step 4: Prepare Card Assignment Data
    # ----------------------------

    card_assignment = {
        "$type": "Feenics.Keep.WebApi.Model.CardAssignmentInfo, Feenics.Keep.WebApi.Model",
        "EncodedCardNumber": int(card_number),
        "DisplayCardNumber": str(card_number),
        "FacilityCode": int(facility_code),
        "ActiveOn": active_on,
        "ExpiresOn": expires_on,
        "CardFormat": {
            "LinkedObjectKey": selected_card_format['Key'],
        },
        "AntiPassbackExempt": False,
        "ExtendedAccess": False,
        "PinExempt": True,
        "IsDisabled": False,
        "ManagerLevel": 0,
        "Note": None,
        "OriginalUseCount": None,
        "CurrentUseCount": 0,
    }

    # ----------------------------
    # Step 5: Prepare User Data for CRM API
    # ----------------------------

    user_data = {
        "$type": "Feenics.Keep.WebApi.Model.PersonInfo, Feenics.Keep.WebApi.Model",
        "CommonName": f"{first_name} {last_name}",
        "GivenName": first_name,
        "Surname": last_name,
        "Addresses": [
            {
                "$type": "Feenics.Keep.WebApi.Model.EmailAddressInfo, Feenics.Keep.WebApi.Model",
                "MailTo": email,
                "Type": "Work"
            },
            {
                "$type": "Feenics.Keep.WebApi.Model.PhoneInfo, Feenics.Keep.WebApi.Model",
                "Number": phone_number,
                "Type": "Mobile"
            }
        ],
        "ObjectLinks": [
            {
                "$type": "Feenics.Keep.WebApi.Model.ObjectLinkItem, Feenics.Keep.WebApi.Model",
                "Relation": "BadgeType",
                "CommonName": badge_type_info.get("CommonName"),
                "Href": badge_type_info.get("Href"),
                "LinkedObjectKey": badge_type_info.get("Key"),
                "MetaDataBson": None
            }
        ],
        "CardAssignments": [card_assignment],
        "Metadata": [
            {
                "$type": "Feenics.Keep.WebApi.Model.MetadataItem, Feenics.Keep.WebApi.Model",
                "Application": "CustomApp",
                "Values": json.dumps({
                    "CardNumber": str(card_number),           # Raw 16-bit Card Number
                    "FacilityCode": str(facility_code)        # Facility Code
                }),
                "ShouldPublishUpdateEvents": False
            }
        ]
    }

    # ----------------------------
    # Step 6: Define Headers for CRM API Request
    # ----------------------------

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    # ----------------------------
    # Step 7: Make CRM API Request to Create User
    # ----------------------------

    try:
        response = SESSION.post(create_person_endpoint, headers=headers, json=user_data)
        response.raise_for_status()

        response_data = response.json()
        user_id = response_data.get("Key")

        if not user_id:
            raise Exception("User ID not found in the response.")

        logger.info(f"User '{first_name} {last_name}' created successfully with ID: {user_id}")
        logger.info(f"Assigned Card Number: {card_number}, Facility Code: {facility_code}")

        # ----------------------------
        # Step 8: Create User in Local Database
        # ----------------------------

        membership_start = datetime.datetime.utcnow()
        membership_end = membership_start + timedelta(hours=membership_duration_hours)

        user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            phone_number=phone_number,
            card_number=card_number,                      # Raw 16-bit Card Number
            formatted_card_number=formatted_card_number,  # 26-bit Formatted Card Number
            facility_code=facility_code,
            membership_start=membership_start,
            membership_end=membership_end,
            external_id=external_id
        )

        db.session.add(user)
        db.session.commit()

        return user, user_id  # Return both user and user_id

    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error during user creation: {http_err}")
        logger.error(f"Response Content: {response.text}")
        raise
    except Exception as err:
        logger.error(f"Error during user creation: {err}")
        raise

def assign_access_levels_to_user(base_address, access_token, instance_id, person_key, access_levels):
    """
    Assigns access levels to a person.

    Args:
        base_address (str): Base URL of the API.
        access_token (str): Bearer token for authentication.
        instance_id (str): Instance ID from the API.
        person_key (str): The unique key of the person (user).
        access_levels (list): List of access level objects, each containing an 'Href'.
    """
    assign_endpoint = f"{base_address}/api/f/{instance_id}/people/{person_key}/accesslevels"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    # Prepare the list of access level Hrefs
    access_level_hrefs = [al['Href'] for al in access_levels if al.get('Href')]

    if not access_level_hrefs:
        logger.error("No valid access level Hrefs found.")
        raise ValueError("Access levels must include 'Href' fields.")

    for href in access_level_hrefs:
        # The payload is a JSON-encoded string of the access level Href
        payload = json.dumps(href)

        # Logging for debugging
        logger.debug(f"Assign Endpoint: {assign_endpoint}")
        logger.debug(f"Access Level Href Payload: {payload}")

        try:
            response = SESSION.put(assign_endpoint, headers=headers, data=payload)
            response.raise_for_status()
            logger.info(f"Access level assigned to user {person_key} successfully.")
        except requests.exceptions.HTTPError as http_err:
            logger.error(f"HTTP error during access level assignment: {http_err}")
            logger.error(f"Response Content: {response.text}")
            raise
        except Exception as err:
            logger.error(f"Error assigning access level to user {person_key}: {err}")
            raise

def get_readers(base_address, access_token, instance_id):
    """
    Retrieves a list of available Readers.

    Returns:
        list: List of reader objects.
    """
    readers_endpoint = f"{base_address}/api/f/{instance_id}/readers"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        response = SESSION.get(readers_endpoint, headers=headers)
        response.raise_for_status()
        readers_data = response.json()

        # Handle both list and dict responses
        if isinstance(readers_data, dict):
            readers = readers_data.get('value', [])
            if not readers:
                logger.warning("No readers found under 'value' key.")
        elif isinstance(readers_data, list):
            readers = readers_data
        else:
            logger.error("Unexpected data format for readers.")
            readers = []

        logger.info(f"Retrieved {len(readers)} readers.")
        return readers
    except Exception as err:
        logger.error(f"Error retrieving readers: {err}")
        raise

def get_card_formats(base_address, access_token, instance_id):
    """
    Retrieves a list of available Card Formats.

    Returns:
        list: List of card format objects.
    """
    card_formats_endpoint = f"{base_address}/api/f/{instance_id}/cardformats"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        response = SESSION.get(card_formats_endpoint, headers=headers)
        response.raise_for_status()
        card_formats_data = response.json()

        # Handle both list and dict responses
        if isinstance(card_formats_data, dict):
            card_formats = card_formats_data.get('value', [])
            if not card_formats:
                logger.warning("No card formats found under 'value' key.")
        elif isinstance(card_formats_data, list):
            card_formats = card_formats_data
        else:
            logger.error("Unexpected data format for card formats.")
            card_formats = []

        logger.info(f"Retrieved {len(card_formats)} card formats.")
        logger.info(card_formats[0])
        return card_formats
    except Exception as err:
        logger.error(f"Error retrieving card formats: {err}")
        raise

def get_controllers(base_address, access_token, instance_id):
    """
    Retrieves a list of available Controllers.

    Returns:
        list: List of controller objects.
    """
    controllers_endpoint = f"{base_address}/api/f/{instance_id}/controllers"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        response = SESSION.get(controllers_endpoint, headers=headers)
        response.raise_for_status()
        controllers_data = response.json()

        # Handle both list and dict responses
        if isinstance(controllers_data, dict):
            controllers = controllers_data.get('value', [])
            if not controllers:
                logger.warning("No controllers found under 'value' key.")
        elif isinstance(controllers_data, list):
            controllers = controllers_data
        else:
            logger.error("Unexpected data format for controllers.")
            controllers = []

        logger.info(f"Retrieved {len(controllers)} controllers.")
        return controllers
    except Exception as err:
        logger.error(f"Error retrieving controllers: {err}")
        raise

TOKEN_VALIDITY_HOURS = int(os.getenv("TOKEN_VALIDITY_HOURS", 24))  # Default to 24 hours if not set

def generate_unlock_token(user_id, external_id):
    token_str = str(uuid.uuid4())
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_VALIDITY_HOURS)

    with app.app_context():
        user = User.query.get(user_id)
        if not user:
            logger.error(f"User with ID {user_id} not found.")
            return None

        unlock_token = UnlockToken(
            token=token_str,
            user_id=user.id,
            expires_at=expires_at,
            external_id=external_id  # Store the external_id
        )
        db.session.add(unlock_token)
        db.session.commit()
        logger.debug(f"Generated unlock token for user {user.id} with external_id {external_id}")

    return token_str

def create_unlock_link(external_id):
    unlock_link = f"{UNLOCK_LINK_BASE_URL}/unlock/{external_id}"
    return unlock_link

# User Creation and Messaging Workflow
# ----------------------------

def process_user_creation(first_name, last_name, email, phone_number, external_id, membership_duration_hours=24):
    """
    Complete workflow to create or update a user in CRM, store membership info, assign access levels,
    generate unlock link, and (optionally) send an SMS.
    """
    try:
        with app.app_context():
            # Step 1: Authenticate
            access_token, instance_id = get_access_token(
                base_address=BASE_ADDRESS,
                instance_name=INSTANCE_NAME,
                username=KEEP_USERNAME,
                password=KEEP_PASSWORD
            )

            # Step 2: Get or Create Badge Type
            badge_types = get_badge_types(BASE_ADDRESS, access_token, instance_id)
            badge_type_info = next((bt for bt in badge_types if bt.get("CommonName") == BADGE_TYPE_NAME), None)

            if not badge_type_info:
                logger.info(f"Badge Type '{BADGE_TYPE_NAME}' does not exist. Creating it now.")
                badge_type_response = create_badge_type(BASE_ADDRESS, access_token, instance_id, BADGE_TYPE_NAME)
                if badge_type_response:
                    badge_type_info = badge_type_response
                else:
                    # If Badge Type already exists (status code 409), retrieve its details
                    badge_type_info = get_badge_type_details(BASE_ADDRESS, access_token, instance_id, BADGE_TYPE_NAME)

            # Step 3: Retrieve all access levels
            access_levels = get_access_levels(BASE_ADDRESS, access_token, instance_id)
            if not access_levels:
                logger.error("No access levels found.")
                raise Exception("No access levels available to assign to the user.")

            # Step 4: Check if user exists in the local database
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                logger.info(f"User with email {email} already exists in the local database.")

                current_time = datetime.datetime.utcnow()

                # If membership_end < now => membership is expired => renew from now
                # Otherwise => membership still active => extend from the existing end
                if existing_user.membership_end < current_time:
                    logger.info("Membership is expired. Renewing from now.")
                    existing_user.membership_end = current_time + timedelta(hours=membership_duration_hours)
                else:
                    logger.info("Membership is active. Extending existing membership.")
                    existing_user.membership_end += timedelta(hours=membership_duration_hours)

                db.session.commit()
                logger.info(
                    f"Updated membership for user {email} to {existing_user.membership_end}"
                )

                # Generate new unlock token with the same external_id
                unlock_token_str = generate_unlock_token(existing_user.id, external_id)
                unlock_link = create_unlock_link(external_id)
                logger.info(f"Generated new unlock token for user {email}")

                # Optionally, reassign or refresh access levels if needed:
                # assign_access_levels_to_user(
                #     base_address=BASE_ADDRESS,
                #     access_token=access_token,
                #     instance_id=instance_id,
                #     person_key=existing_user.external_id,
                #     access_levels=access_levels
                # )

                return  # Stop here after handling existing user

            # Step 5: Create the user via CRM API and store in local database
            user, user_id = create_user(
                base_address=BASE_ADDRESS,
                access_token=access_token,
                instance_id=instance_id,
                first_name=first_name,
                last_name=last_name,
                email=email,
                phone_number=phone_number,
                badge_type_info=badge_type_info,
                membership_duration_hours=membership_duration_hours,
                external_id=external_id  # Pass the external_id
            )

            # Step 6: Assign Access Levels to the User
            assign_access_levels_to_user(
                base_address=BASE_ADDRESS,
                access_token=access_token,
                instance_id=instance_id,
                person_key=user_id,
                access_levels=access_levels
            )

            # Optional: Wait briefly for access level assignment
            time.sleep(2)

            # Step 7: Generate Unlock Token and Link
            unlock_token_str = generate_unlock_token(user.id, external_id)
            unlock_link = create_unlock_link(external_id)

    except Exception as e:
        logger.exception(f"Error in processing user creation: {e}")

# ----------------------------
# Unlock Token Management
# ----------------------------

def validate_unlock_token_by_external_id(external_id):
    """
    Validates the unlock token using external_id.
    """
    with app.app_context():
        unlock_tokens = UnlockToken.query.filter_by(external_id=external_id).order_by(UnlockToken.created_at.desc()).all()

        if not unlock_tokens:
            return False, "Invalid unlock link."

        # Find the most recent valid unlock token
        for unlock_token in unlock_tokens:
            if not unlock_token.used and datetime.datetime.utcnow() < unlock_token.expires_at and unlock_token.user.is_membership_active():
                return True, unlock_token

        return False, "No valid unlock token found. Please purchase a new pass or contact support."

# ----------------------------
# Flask Routes
# ----------------------------

@app.route('/reset_database', methods=['POST'])
def reset_database():
    if not app.config['DEBUG']:
        abort(403, description="Forbidden")

    try:
        db.drop_all()
        db.create_all()
        return jsonify({'status': 'Database reset successfully'}), 200
    except Exception as e:
        logger.exception(f"Error resetting database: {e}")
        return jsonify({'error': 'Failed to reset database'}), 500

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    # Log raw request data
    raw_data = request.data
    logger.debug(f"Raw request data: {raw_data}")

    # Attempt to parse JSON data
    data = request.get_json()

    # If JSON data is not present, fall back to form data
    if not data:
        data = request.form.to_dict()
        logger.debug("Parsed form data instead of JSON.")

    logger.info(f"Received webhook data: {data}")

    # Extract fields with flexibility in field names
    first_name = (
        data.get('first_name') or
        data.get('firstname') or
        data.get('customData', {}).get('first_name')
    )
    last_name = (
        data.get('last_name') or
        data.get('lastname') or
        data.get('customData', {}).get('last_name')
    )
    email = data.get('email') or data.get('customData', {}).get('email')
    phone_number = (
        data.get('phone') or
        data.get('phone_number') or
        data.get('customData', {}).get('phone')
    )
    external_id = (
        data.get('external_id') or
        data.get('contact_id') or
        data.get('id') or
        data.get('customData', {}).get('external_user_id')
    )
    # ----------------------------
    # Extract the duration from the webhook data
    # ----------------------------
    membership_duration_hours = (
        data.get('membership_duration_hours') or
        data.get('duration') or
        data.get('customData', {}).get('membership_duration_hours')
    )

    # Log extracted fields
    logger.debug(f"Extracted first_name: {first_name}")
    logger.debug(f"Extracted last_name: {last_name}")
    logger.debug(f"Extracted email: {email}")
    logger.debug(f"Extracted phone_number: {phone_number}")
    logger.debug(f"Extracted external_id: {external_id}")
    logger.debug(f"Extracted membership_duration_hours: {membership_duration_hours}")

    # Validate required fields
    if not all([first_name, last_name, email, phone_number, external_id]):
        logger.warning(f"Missing required fields. Received data: {data}")
        return jsonify({'error': 'Missing required fields.'}), 400

    # Validate phone number format
    if not validate_phone_number(phone_number):
        logger.warning(f"Invalid phone number format: {phone_number}")
        return jsonify({'error': 'Invalid phone number format.'}), 400

    # ----------------------------
    # Validate and set membership_duration_hours
    # ----------------------------
    if membership_duration_hours is None:
        membership_duration_hours = 24  # Default value if not provided
        logger.info("Membership duration not provided. Using default of 24 hours.")
    else:
        try:
            membership_duration_hours = int(membership_duration_hours)
            if membership_duration_hours <= 0:
                raise ValueError("Membership duration must be a positive integer.")
        except ValueError:
            logger.warning(f"Invalid membership duration: {membership_duration_hours}")
            return jsonify({'error': 'Invalid membership duration. It must be a positive integer.'}), 400

    logger.info(f"Processing user: {first_name} {last_name}, Email: {email}, Phone: {phone_number}, External ID: {external_id}, Membership Duration: {membership_duration_hours} hours")

    # Process user creation in a separate thread with application context
    threading.Thread(target=process_user_creation, args=(
        first_name, last_name, email, phone_number, external_id, membership_duration_hours)).start()

    return jsonify({'status': 'User creation in progress'}), 200


from geopy.distance import geodesic  # Add this import
@app.route('/unlock/<external_id>', methods=['GET', 'POST'])
def handle_unlock(external_id):
    logger.debug(f"Received unlock request for external_id: {external_id}")
    if request.method == 'GET':
        is_valid, result = validate_unlock_token_by_external_id(external_id)

        if not is_valid:
            logger.warning(f"Unlock attempt failed: {result}")
            # Render error template with the message
            return render_template('error.html', message=result), 400

        # Pass external_id to the template
        return render_template('unlock.html', external_id=external_id)
    elif request.method == 'POST':
        logger.debug(f"Processing unlock for external_id: {external_id}")
        is_valid, result = validate_unlock_token_by_external_id(external_id)

        if not is_valid:
            logger.warning(f"Unlock attempt failed: {result}")
            return render_template('error.html', message=result), 400

        unlock_token = result  # Now we have the valid unlock_token

        # Get the user's submitted location
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')

        if not latitude or not longitude:
            logger.warning("Location data not provided.")
            return render_template('error.html', message='Location data is required to unlock the door.'), 400

        try:
            user_lat = float(latitude)
            user_lon = float(longitude)
        except ValueError:
            logger.warning("Invalid location data.")
            return render_template('error.html', message='Invalid location data received.'), 400

        # Gym's location (latitude and longitude)
        GYM_LATITUDE = 36.2020864   # Replace with your gym's actual latitude
        GYM_LONGITUDE = -86.6091008 # Replace with your gym's actual longitude
        MAX_DISTANCE_METERS = 3000.4080393305367  # Maximum allowed distance in meters

        # Compute the distance between the user and the gym
        user_location = (user_lat, user_lon)
        gym_location = (GYM_LATITUDE, GYM_LONGITUDE)
        distance = geodesic(user_location, gym_location).meters

        logger.debug(f"User location: {user_location}")
        logger.debug(f"Gym location: {gym_location}")
        logger.debug(f"Distance to gym: {distance} meters")

        if distance > MAX_DISTANCE_METERS:
            logger.warning(f"User is too far from the gym. Distance: {distance} meters.")
            return render_template('error.html', message='You must be at the gym to unlock the door.'), 400

        # Check if the membership is still active
        if not unlock_token.user.is_membership_active():
            logger.warning("Membership is no longer active.")
            return render_template('error.html', message='Your membership has expired. Please renew to continue accessing the gym.'), 400

        # User is at the gym and membership is active, proceed with unlock

        # Mark the token as used
        with app.app_context():
            unlock_token.used = True
            db.session.commit()

        # Simulate the unlock
        card_number = unlock_token.user.card_number
        facility_code = unlock_token.user.facility_code
        threading.Thread(target=simulate_unlock, args=(card_number, facility_code)).start()

        # Render a response template or return a message
        return render_template('unlocking.html')


def simulate_unlock(card_number, facility_code):
    """
    Simulates the card read to unlock the door using the 16-bit card_number.
    """
    try:
        with app.app_context():
            # Authenticate
            access_token, instance_id = get_access_token(
                base_address=BASE_ADDRESS,
                instance_name=INSTANCE_NAME,
                username=KEEP_USERNAME,
                password=KEEP_PASSWORD
            )

            # Retrieve required components
            readers = get_readers(BASE_ADDRESS, access_token, instance_id)
            if not readers:
                logger.error("No Readers found.")
                return

            # Log available readers
            logger.info("Available Readers:")
            for reader_item in readers:
                logger.info(f"Reader Name: {reader_item.get('CommonName')}, Key: {reader_item.get('Key')}")

            # Specify the reader's name
            reader_name = 'Front door'  # Replace with your reader's name from logs
            reader = next((r for r in readers if r.get('CommonName') == reader_name), None)
            if not reader:
                logger.warning(f"Specified Reader '{reader_name}' not found. Using the first available reader.")
                reader = readers[0]
            logger.info(f"Using reader: {reader.get('CommonName')}")

            card_formats = get_card_formats(BASE_ADDRESS, access_token, instance_id)
            if not card_formats:
                logger.error("No Card Formats found.")
                return

            # Use the first available card format
            card_format = card_formats[0]
            logger.info(f"Using card format: {card_format.get('CommonName')}")

            controllers = get_controllers(BASE_ADDRESS, access_token, instance_id)
            if not controllers:
                logger.error("No Controllers found.")
                return

            # Log available controllers
            logger.info("Available Controllers:")
            for controller_item in controllers:
                logger.info(f"Controller Name: {controller_item.get('CommonName')}, Key: {controller_item.get('Key')}")

            # Specify the controller's name
            controller_name = 'Controller'  # Replace with your controller's name from logs
            controller = next((c for c in controllers if c.get('CommonName') == controller_name), None)
            if not controller:
                logger.warning(f"Specified Controller '{controller_name}' not found. Using the first available controller.")
                controller = controllers[0]
            logger.info(f"Using controller: {controller.get('CommonName')}")

            # Simulate Card Read
            success = simulate_card_read(
                base_address=BASE_ADDRESS,
                access_token=access_token,
                instance_id=instance_id,
                reader=reader,
                card_format=card_format,
                controller=controller,
                reason=SIMULATION_REASON,
                facility_code=facility_code,
                card_number=card_number  # Use raw 16-bit card_number
            )

            if success:
                logger.info("Unlock simulation successful.")
            else:
                logger.error("Unlock simulation failed.")

    except Exception as e:
        logger.exception(f"Error in simulating unlock: {e}")

def simulate_card_read(base_address, access_token, instance_id, reader, card_format, controller, reason, facility_code, card_number):
    """
    Simulates a card read by publishing a simulateCardRead event using the formatted_card_number.

    Returns:
        bool: True if successful, False otherwise.
    """
    event_endpoint = f"{base_address}/api/f/{instance_id}/eventmessagesink"

    # Ensure formatted_card_number and facility_code are integers
    try:
        card_number_int = int(card_number)
        facility_code_int = int(facility_code)
    except ValueError as e:
        logger.error(f"Invalid card number or facility code: {e}")
        return False

    # Construct EventData
    event_data = {
        "Reason": reason,
        "FacilityCode": facility_code_int,
        "EncodedCardNumber": card_number_int,
    }

    logger.info(f"Event Data before encoding: {event_data}")

    # Convert EventData to BSON and then to Base64
    event_data_bson = BSON.encode(event_data)
    event_data_base64 = base64.b64encode(event_data_bson).decode('utf-8')

    logger.info(f"EventDataBsonBase64: {event_data_base64}")

    # Construct the payload
    payload = {
        "$type": "Feenics.Keep.WebApi.Model.EventMessagePosting, Feenics.Keep.WebApi.Model",
        "OccurredOn": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + 'Z',
        "AppKey": "MercuryCommands",
        "EventTypeMoniker": {
            "$type": "Feenics.Keep.WebApi.Model.MonikerItem, Feenics.Keep.WebApi.Model",
            "Namespace": "MercuryServiceCommands",
            "Nickname": "mercury:command-simulateCardRead"
        },
        "RelatedObjects": [
            {
                "$type": "Feenics.Keep.WebApi.Model.ObjectLinkItem, Feenics.Keep.WebApi.Model",
                "Href": reader['Href'],
                "LinkedObjectKey": reader['Key'],
                "CommonName": reader['CommonName'],
                "Relation": "Reader",
                "MetaDataBson": None
            },
            {
                "$type": "Feenics.Keep.WebApi.Model.ObjectLinkItem, Feenics.Keep.WebApi.Model",
                "Href": card_format['Href'],
                "LinkedObjectKey": card_format['Key'],
                "CommonName": card_format['CommonName'],
                "Relation": "CardFormat",
                "MetaDataBson": None
            },
            {
                "$type": "Feenics.Keep.WebApi.Model.ObjectLinkItem, Feenics.Keep.WebApi.Model",
                "Href": controller['Href'],
                "LinkedObjectKey": controller['Key'],
                "CommonName": controller['CommonName'],
                "Relation": "Controller",
                "MetaDataBson": None
            }
        ],
        "EventDataBsonBase64": event_data_base64
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        response = SESSION.post(event_endpoint, headers=headers, json=payload)
        response.raise_for_status()
        logger.info("Card read simulation event published successfully.")
        return True
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error during event publishing: {http_err}")
        logger.error(f"Response Status Code: {response.status_code}")
        logger.error(f"Response Content: {response.text}")
        return False
    except Exception as err:
        logger.error(f"Error during event publishing: {err}")
        return False

# ----------------------------
# Main Execution
# ----------------------------

if __name__ == "__main__":
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000)
