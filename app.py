import os
import sys
import json
import uuid
import random
import base64
import logging
import threading
import datetime
from datetime import datetime, timezone, timedelta
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
from sqlalchemy.dialects.postgresql import JSONB

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



# Replace your existing Event model with this:

class Event(db.Model):
    __tablename__ = 'event'
    id          = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    occurred_on = db.Column(db.DateTime, index=True, nullable=False)
    event_type  = db.Column(db.String(100), nullable=True)
    reader      = db.Column(db.String(100), nullable=True)
    door        = db.Column(db.String(100), nullable=True)
    person      = db.Column(db.String(200), nullable=True)
    event_data  = db.Column(JSONB, nullable=True)
    created_at  = db.Column(
        db.DateTime,
        default=lambda: datetime.utcnow(),   # ← use a lambda so .utcnow() is always called
        nullable=False
    )

    __table_args__ = (db.Index('ix_event_occurred_on', 'occurred_on'),)





class User(db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=False, nullable=False)
    phone_number = db.Column(db.String(20), unique=False, nullable=False)
    facility_code = db.Column(db.Integer, nullable=False)
    card_number = db.Column(db.Integer, unique=True, nullable=False)          # Raw 16-bit Card Number
    formatted_card_number = db.Column(db.String(20), unique=True, nullable=False)  # 26-bit Formatted Card Number
    membership_start = db.Column(db.DateTime, nullable=False)
    membership_end = db.Column(db.DateTime, nullable=False)

    # NEW COLUMN: Feenics Key (the real MongoDB ObjectId from Feenics)
    feenics_key = db.Column(db.String(50), unique=True, nullable=True)

    # External ID from a 3rd-party system (if needed)
    external_id = db.Column(db.String(50), unique=False, nullable=True)

    def is_membership_active(self):
        now = datetime.datetime.utcnow()
        return self.membership_start <= now <= self.membership_end

# And replace your existing UnlockToken model with this:

class UnlockToken(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    token       = db.Column(db.String(36), nullable=False)
    user_id     = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at  = db.Column(
        db.DateTime,
        default=lambda: datetime.utcnow(),   # ← same trick here
        nullable=False
    )
    expires_at  = db.Column(db.DateTime, nullable=False)
    used        = db.Column(db.Boolean, default=False)
    external_id = db.Column(db.String(50), nullable=False)

    user = db.relationship('User', backref=db.backref('unlock_tokens', lazy=True))

    def is_valid(self):
        now = datetime.utcnow()
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
def fetch_recent_events(base_address: str,
                        access_token: str,
                        instance_id: str,
                        page_size: int = 250,
                        since_iso: str | None = None,
                        max_events: int = 1000) -> list[dict]:
    """
    Pulls raw events from Keep/Feenics and gives you a lightweight list
    that already contains the decoded BSON payload.

    Args:
        page_size   – max 1000 (Keep API hard‑limit)
        since_iso   – optional ISO‑8601 UTC string (e.g. 2025‑04‑18T15:00:00Z)
        max_events  – safety cap so we don’t endlessly loop
        
    Returns:
        List of dicts ⇒ [{occurred_on, event_type, description, reader,
                          person, door, event_data}, …]
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    endpoint = f"{base_address}/api/f/{instance_id}/events"

    # Convert ?since=… to a datetime for local filtering
    since_dt = None
    if since_iso:
        since_dt = datetime.datetime.fromisoformat(
            since_iso.replace("Z", "+00:00")
        )

    collected: list[dict] = []
    page = 0
    while len(collected) < max_events:
        params = {
            "page": page,
            "pageSize": page_size,
            "includeSubFolders": "false",
            "includeSharedInstances": "false",
            "spanScope": "false",
            "requiresAck": "false",
            "priorityThreshold": 0
        }

        resp = SESSION.get(endpoint, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        batch = resp.json()
        if not batch:               # no more data
            break

        for ev in batch:
            occurred_on = ev.get("OccurredOn")          # ISO‑8601 string
            if since_dt and occurred_on:
                ev_dt = datetime.datetime.fromisoformat(
                    occurred_on.replace("Z", "+00:00")
                )
                if ev_dt < since_dt:
                    continue     # too old – skip

            # Decode the BSON payload (may fail for some system events)
            try:
                raw_b64 = ev.get("EventDataBsonBase64", "")
                bson_bytes = base64.b64decode(raw_b64)
                event_data = BSON(bson_bytes).decode()
            except Exception:
                event_data = {}

            collected.append({
                "occurred_on": occurred_on,
                "event_type": ev.get("EventTypeMoniker", {}).get("Nickname"),
                "description": ev.get("EventTypeMoniker", {}).get("Namespace"),
                "reader": next((o["CommonName"]
                                for o in ev.get("RelatedObjects", [])
                                if o.get("Relation") == "Reader"), None),
                "door": next((o["CommonName"]
                              for o in ev.get("RelatedObjects", [])
                              if o.get("Relation") == "Door"), None),
                "person": next((o["CommonName"]
                                for o in ev.get("RelatedObjects", [])
                                if o.get("Relation") == "Person"), None),
                "event_data": event_data
            })

            if len(collected) >= max_events:
                break
        page += 1

    return collected


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
from datetime import datetime, timedelta
from sqlalchemy import func

from sqlalchemy.exc import ProgrammingError
from sqlalchemy import inspect




def sync_events_job():
    """
    1) On first run (empty table), fetch last 6 months.
    2) Afterwards fetch only events newer than the newest in DB.
    3) Purge anything older than 6 months.
    """
    with app.app_context():
        insp = inspect(db.engine)
        if not insp.has_table(Event.__tablename__):
            logger.warning("Event table not yet created; skipping sync_events_job.")
            return

        # find the newest event we already have
        last_dt = db.session.query(func.max(Event.occurred_on)).scalar()

        # decide how far back to pull
        if last_dt is None:
            since_dt = datetime.utcnow() - timedelta(days=180)
        else:
            since_dt = last_dt

        since_iso = since_dt.replace(microsecond=0).isoformat() + 'Z'

        # pull from Feenics
        token, inst_id = get_access_token(
            BASE_ADDRESS, INSTANCE_NAME, KEEP_USERNAME, KEEP_PASSWORD
        )
        raw_events = fetch_recent_events(
            base_address=BASE_ADDRESS,
            access_token=token,
            instance_id=inst_id,
            page_size=500,
            since_iso=since_iso,
            max_events=5000
        )

        # upsert into local DB
        for ev in raw_events:
            ev_dt = datetime.fromisoformat(ev['occurred_on'].replace('Z','+00:00'))
            exists = Event.query.filter_by(
                occurred_on=ev_dt,
                event_data=ev['event_data']
            ).first()
            if exists:
                continue

            db.session.add(Event(
                occurred_on = ev_dt,
                event_type  = ev.get('event_type'),
                reader      = ev.get('reader'),
                door        = ev.get('door'),
                person      = ev.get('person'),
                event_data  = ev.get('event_data')
            ))
        db.session.commit()

        # purge >6 months old
        cutoff = datetime.utcnow() - timedelta(days=180)
        Event.query.filter(Event.occurred_on < cutoff).delete()
        db.session.commit()
def create_user(base_address, access_token, instance_id, first_name, last_name,
                email, phone_number, badge_type_info, membership_duration_hours,
                external_id):
    """
    Creates a new user in the Keep by Feenics system and stores it in our local DB.
    Returns: (user, feenics_person_key)
    """
    create_person_endpoint = f"{base_address}/api/f/{instance_id}/people"

    # 1. Generate raw 16-bit card number
    card_number = generate_card_number()
    facility_code = FACILITY_CODE

    # 2. Format to 26-bit HID
    formatted_card_number, error_message = format_hid_26bit_h10301(facility_code, card_number)
    if not formatted_card_number:
        logger.error(f"Error formatting card number: {error_message}")
        raise ValueError(error_message)

    # 3. Prepare active/expiration times
    active_on = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    expires_on = (datetime.datetime.utcnow() + timedelta(hours=membership_duration_hours))\
                    .replace(microsecond=0).isoformat() + "Z"

    # 4. Get card formats from Feenics
    card_formats = get_card_formats(base_address, access_token, instance_id)
    if not card_formats:
        raise Exception("No card formats available to assign to the card.")

    selected_card_format = card_formats[0]

    # 5. Construct the card assignment
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

    # 6. Construct user data for Feenics
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
                    "CardNumber": str(card_number),
                    "FacilityCode": str(facility_code)
                }),
                "ShouldPublishUpdateEvents": False
            }
        ]
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    # 7. Create the person in Feenics
    try:
        response = SESSION.post(create_person_endpoint, headers=headers, json=user_data)
        response.raise_for_status()

        response_data = response.json()
        feenics_person_key = response_data.get("Key")  # This is Feenics's real Mongo ObjectId

        if not feenics_person_key:
            raise Exception("User ID (Feenics Key) not found in Feenics response.")

        logger.info(f"User '{first_name} {last_name}' created in Feenics with Key={feenics_person_key}")

        # 8. Store in our local DB
        membership_start = datetime.datetime.utcnow()
        membership_end = membership_start + timedelta(hours=membership_duration_hours)

        user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            phone_number=phone_number,
            card_number=card_number,
            formatted_card_number=formatted_card_number,
            facility_code=facility_code,
            membership_start=membership_start,
            membership_end=membership_end,

            # NOW store Feenics's real ObjectId
            feenics_key=feenics_person_key,
            # Keep external_id if it's coming from outside system
            external_id=external_id
        )

        db.session.add(user)
        db.session.commit()

        return user, feenics_person_key

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

def process_user_creation(first_name, last_name, email, phone_number,
                          external_id, membership_duration_hours=24):
    """
    Creates or updates a user in Feenics, stores membership info locally,
    assigns access levels, generates unlock link, etc.
    """
    try:
        with app.app_context():
            # 1. Authenticate with Feenics
            access_token, instance_id = get_access_token(
                base_address=BASE_ADDRESS,
                instance_name=INSTANCE_NAME,
                username=KEEP_USERNAME,
                password=KEEP_PASSWORD
            )

            # 2. Get or create the desired Badge Type
            badge_types = get_badge_types(BASE_ADDRESS, access_token, instance_id)
            badge_type_info = next(
                (bt for bt in badge_types if bt.get("CommonName") == BADGE_TYPE_NAME), None
            )
            if not badge_type_info:
                # create_badge_type returns the new object or None if 409
                badge_type_response = create_badge_type(
                    BASE_ADDRESS, access_token, instance_id, BADGE_TYPE_NAME
                )
                if badge_type_response:
                    badge_type_info = badge_type_response
                else:
                    # If it was already existing but we got 409,
                    # then fetch details again
                    badge_type_info = get_badge_type_details(
                        BASE_ADDRESS, access_token, instance_id, BADGE_TYPE_NAME
                    )

            # 3. Retrieve all access levels from Feenics
            access_levels = get_access_levels(BASE_ADDRESS, access_token, instance_id)
            if not access_levels:
                raise Exception("No access levels available to assign to the user.")

            # 4. Check local DB for existing user
            existing_user = User.query.filter_by(email=email).first()

            if existing_user:
                logger.info(f"User with email {email} already exists in local DB.")
                
                # Extend membership in local DB
                current_time = datetime.datetime.utcnow()
                new_end = max(existing_user.membership_end, current_time) + \
                          timedelta(hours=membership_duration_hours)
                existing_user.membership_end = new_end
                db.session.commit()

                # REASSIGN ACCESS in Feenics, using the real Key
                # If existing_user.feenics_key is None, it means the user was never
                # actually created in Feenics. In that case, you might need to call create_user
                # or handle that scenario. Otherwise:
                if existing_user.feenics_key:
                    assign_access_levels_to_user(
                        base_address=BASE_ADDRESS,
                        access_token=access_token,
                        instance_id=instance_id,
                        # MUST pass the Feenics Key, not external_id
                        person_key=existing_user.feenics_key,
                        access_levels=access_levels
                    )
                    logger.info("Reassigned access levels in Feenics for existing user.")
                else:
                    logger.warning("Existing user has no feenics_key - cannot update in Feenics.")

                # Generate new unlock token, etc.
                unlock_token_str = generate_unlock_token(existing_user.id, external_id)
                unlock_link = create_unlock_link(external_id)
                logger.info(f"Membership extended. Generated unlock link: {unlock_link}")

                return

            else:
                # 5. Brand new user in Feenics + local DB
                user, feenics_person_key = create_user(
                    base_address=BASE_ADDRESS,
                    access_token=access_token,
                    instance_id=instance_id,
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    phone_number=phone_number,
                    badge_type_info=badge_type_info,
                    membership_duration_hours=membership_duration_hours,
                    external_id=external_id
                )

                # 6. Assign Access Levels in Feenics
                assign_access_levels_to_user(
                    base_address=BASE_ADDRESS,
                    access_token=access_token,
                    instance_id=instance_id,
                    # Now we pass the real Feenics Key
                    person_key=feenics_person_key,
                    access_levels=access_levels
                )

                # Wait a bit, just in case
                time.sleep(2)

                # 7. Generate unlock token and link
                unlock_token_str = generate_unlock_token(user.id, external_id)
                unlock_link = create_unlock_link(external_id)
                logger.info(f"User created. Unlock link: {unlock_link}")

    except Exception as e:
        logger.exception(f"Error in processing user creation: {e}")

# ----------------------------
# Unlock Token Management
# ----------------------------

def validate_unlock_token_by_external_id(external_id):
    """
    Validate an unlock‑token using the caller‑supplied external_id.

    Returns
    -------
    (bool, UnlockToken | str)
        • (True,  <UnlockToken>)  – when a still‑valid token is found
        • (False, <error‑message>)
    """
    external_id = str(external_id)                   # ← ensure string match

    with app.app_context():
        unlock_tokens = (UnlockToken.query
                         .filter_by(external_id=external_id)
                         .order_by(UnlockToken.created_at.desc())
                         .all())

        if not unlock_tokens:
            return False, "Invalid unlock link."

        # pick the newest token that is unused, unexpired, and owned by a
        # member whose membership is still active
        for token in unlock_tokens:
            if (not token.used and
                datetime.datetime.utcnow() < token.expires_at and
                token.user.is_membership_active()):
                return True, token

        return False, (
            "No valid unlock token found. Please purchase a new pass or "
            "contact support."
        )


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
    
# ------------------------------------------------------------------
# JSON‑safe helper
# ------------------------------------------------------------------
import base64
import datetime as _dt

def _scrub_bytes(obj):
    """
    Recursively convert objects that JSON can't handle:
        • bytes / bytearray  -> base‑64 string
        • datetime / date    -> ISO‑8601 string
    Works for nested dicts / lists.
    """
    if isinstance(obj, (bytes, bytearray)):
        return base64.b64encode(obj).decode()
    if isinstance(obj, (_dt.datetime, _dt.date)):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _scrub_bytes(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub_bytes(v) for v in obj]
    return obj


# ------------------------------------------------------------------
# /activity  – recent unlock / door / exit events feed
# ------------------------------------------------------------------
@app.route('/activity', methods=['GET'])
def activity_feed():
    """
    GET /activity
      ?limit=<1‑1000>           (default 100)
      ?since=<ISO‑8601‑UTC>     (optional; e.g. 2025‑04‑18T14:00:00Z)
      ?search=<string>          (optional; filters by Person or User.CommonName)

    Returns a JSON list of events, already scrubbed for JSON safety.
    """
    try:
        # 1) authenticate
        token, inst_id = get_access_token(
            base_address=BASE_ADDRESS,
            instance_name=INSTANCE_NAME,
            username=KEEP_USERNAME,
            password=KEEP_PASSWORD
        )

        # 2) parse query params
        try:
            limit = max(1, min(int(request.args.get("limit", "100")), 1000))
        except ValueError:
            limit = 100
        since_iso = request.args.get("since")    # e.g. "2025-04-18T14:00:00Z"
        search_q  = request.args.get("search", "").strip().lower()

        # 3) fetch raw events
        events_raw = fetch_recent_events(
            base_address=BASE_ADDRESS,
            access_token=token,
            instance_id=inst_id,
            page_size=min(limit, 1000),
            since_iso=since_iso,
            max_events=limit
        )

        # 4) if search supplied, filter by Person or User.CommonName
        if search_q:
            filtered = []
            for ev in events_raw:
                ed = ev.get("event_data", {}) or {}
                # Person from payload
                person_str = ed.get("Person") or ""
                # User.CommonName from payload
                user_obj   = ed.get("User") or {}
                user_str   = user_obj.get("CommonName") or ""
                if (search_q in person_str.lower()) or (search_q in user_str.lower()):
                    filtered.append(ev)
            events_to_return = filtered
        else:
            events_to_return = events_raw

        # 5) scrub bytes/datetimes and return
        safe = _scrub_bytes(events_to_return)
        return jsonify({"events": safe}), 200

    except requests.HTTPError as http_err:
        logger.error(f"Feenics API error while fetching activity: {http_err}")
        return jsonify({"error": "Failed to reach Feenics API"}), 502
    except Exception as e:
        logger.exception(f"Unhandled error in /activity: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/activity_view', methods=['GET'])
# ------------------------------------------------------------------
# /activity_view  – HTML search page for recent events
# ------------------------------------------------------------------
def activity_view():
    """
    Renders the UI at templates/activity.html.
    The page’s JS calls /activity?search=… to get data.
    """
    return render_template("activity.html")


# Register the route so *all* of these work:
#   /activity_view         /activity_view/         /activity-view
app.add_url_rule("/activity_view",  view_func=_render_activity_page, methods=["GET"], strict_slashes=False)
app.add_url_rule("/activity_view/", view_func=_render_activity_page, methods=["GET"], strict_slashes=False)
app.add_url_rule("/activity-view",  view_func=_render_activity_page, methods=["GET"], strict_slashes=False)






from geopy.distance import geodesic  # Add this import
@app.route('/unlock/<external_id>', methods=['GET', 'POST'])
def handle_unlock(external_id):
    logger.debug(f"Received unlock request for external_id: {external_id}")
    
    if request.method == 'GET':
        # Validate the token
        is_valid, result = validate_unlock_token_by_external_id(external_id)
        if not is_valid:
            logger.warning(f"Unlock attempt failed: {result}")
            # Render error template with the message
            return render_template('error.html', message=result), 400

        # Render the unlock page which includes the 3D model & JS
        return render_template('unlock.html', external_id=external_id)

    # POST method => attempt to unlock
    elif request.method == 'POST':
        # Check if it's AJAX or not
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        logger.debug(f"Processing unlock (AJAX={is_ajax}) for external_id: {external_id}")

        # Validate the token
        is_valid, result = validate_unlock_token_by_external_id(external_id)
        if not is_valid:
            logger.warning(f"Unlock attempt failed: {result}")
            # CHANGED: Always render error.html, even for AJAX
            return render_template('error.html', message=result), 400

        unlock_token = result  # The valid UnlockToken object

        # Get the user's submitted location
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')

        if not latitude or not longitude:
            msg = 'Location data is required to unlock the door.'
            logger.warning(msg)
            # CHANGED: Always render error.html, even for AJAX
            return render_template('error.html', message=msg), 400

        # Validate lat/long
        try:
            user_lat = float(latitude)
            user_lon = float(longitude)
        except ValueError:
            msg = 'Invalid location data received.'
            logger.warning(msg)
            # CHANGED: Always render error.html, even for AJAX
            return render_template('error.html', message=msg), 400

        # Gym's location (latitude and longitude)
        GYM_LATITUDE = 36.2020864
        GYM_LONGITUDE = -86.6091008
        MAX_DISTANCE_METERS = 3000.4080393305367  # 3km, for example

        # Compute the distance between the user and the gym
        user_location = (user_lat, user_lon)
        gym_location = (GYM_LATITUDE, GYM_LONGITUDE)
        distance = geodesic(user_location, gym_location).meters

        logger.debug(f"User location: {user_location}")
        logger.debug(f"Gym location: {gym_location}")
        logger.debug(f"Distance to gym: {distance} meters")

        if distance > MAX_DISTANCE_METERS:
            msg = 'You must be at the gym to unlock the door.'
            logger.warning(f"{msg} Distance: {distance} meters.")
            # CHANGED: Always render error.html, even for AJAX
            return render_template('error.html', message=msg), 400

        # Check if the membership is still active
        if not unlock_token.user.is_membership_active():
            msg = 'Your membership has expired. Please renew to continue accessing the gym.'
            logger.warning(msg)
            # CHANGED: Always render error.html, even for AJAX
            return render_template('error.html', message=msg), 400

        # Everything is okay => mark token as used and simulate unlock
        with app.app_context():
            unlock_token.used = True
            db.session.commit()

        # Fire off the unlock in a thread so we don't block
        card_number = unlock_token.user.card_number
        facility_code = unlock_token.user.facility_code
        threading.Thread(target=simulate_unlock, args=(card_number, facility_code)).start()

        if is_ajax:
            # Return a JSON success so the front-end JS can change the indicator to green
            return jsonify({"success": True})
        else:
            # Standard response if not using AJAX
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
def backfill_feenics_keys():
    """
    Loops through all existing users who have no feenics_key in our local DB,
    creates them in Feenics using create_user(...), and updates the record 
    with the newly returned feenics_key.
    """
    try:
        # 1. Authenticate with Feenics
        access_token, instance_id = get_access_token(
            base_address=BASE_ADDRESS,
            instance_name=INSTANCE_NAME,
            username=KEEP_USERNAME,
            password=KEEP_PASSWORD
        )

        # 2. Get or create the Badge Type
        badge_types = get_badge_types(BASE_ADDRESS, access_token, instance_id)
        badge_type_info = next(
            (bt for bt in badge_types if bt.get("CommonName") == BADGE_TYPE_NAME), 
            None
        )
        if not badge_type_info:
            # Attempt to create the badge type if it doesn't exist
            badge_type_response = create_badge_type(
                BASE_ADDRESS, access_token, instance_id, BADGE_TYPE_NAME
            )
            if badge_type_response:
                badge_type_info = badge_type_response
            else:
                # If it was already existing but we got a 409, fetch details again
                badge_type_info = get_badge_type_details(
                    BASE_ADDRESS, access_token, instance_id, BADGE_TYPE_NAME
                )

        if not badge_type_info:
            logger.error(f"Cannot proceed: Badge type '{BADGE_TYPE_NAME}' not found or created.")
            return

        # 3. Find all Users missing feenics_key
        users_missing_key = User.query.filter(User.feenics_key.is_(None)).all()
        if not users_missing_key:
            logger.info("No users missing Feenics key. Backfill not needed.")
            return

        logger.info(f"Found {len(users_missing_key)} user(s) with no feenics_key. Backfilling...")

        # 4. Process each user
        for local_user in users_missing_key:
            try:
                # We'll pick a membership_duration_hours (default 24 here),
                # or you can use the user's existing membership_end to calculate 
                # how many hours are left, etc.
                default_duration = 24

                # Call the existing Feenics creation logic
                # This will create them in Feenics and set user.feenics_key
                new_user, feenics_person_key = create_user(
                    base_address=BASE_ADDRESS,
                    access_token=access_token,
                    instance_id=instance_id,
                    first_name=local_user.first_name,
                    last_name=local_user.last_name,
                    email=local_user.email,
                    phone_number=local_user.phone_number,
                    badge_type_info=badge_type_info,
                    membership_duration_hours=default_duration,
                    external_id=local_user.external_id
                )

                logger.info(
                    f"Backfilled feenics_key for user id={local_user.id} (Local DB). "
                    f"Assigned Feenics Key={feenics_person_key}"
                )
            except Exception as e:
                logger.exception(
                    f"Error creating Feenics user for local user id={local_user.id}: {e}"
                )

        logger.info("Backfill operation completed.")

    except Exception as e:
        logger.exception(f"Failed to run backfill_feenics_keys(): {e}")

from sqlalchemy.exc import ProgrammingError

def init_db():
    """Creates all tables (and indexes), but ignores a DuplicateTable on our index."""
    with app.app_context():
        try:
            db.create_all()
        except ProgrammingError as e:
            # if our only complaint is “relation ix_event_occurred_on already exists”, ignore it
            if 'ix_event_occurred_on' in str(e.orig):
                logger.info("Index ix_event_occurred_on already exists, skipping.")
            else:
                # some other SQL error—re‑raise so you don’t hide it
                raise

# … later, instead of calling db.create_all() directly, call init_db():

from apscheduler.schedulers.background import BackgroundScheduler

# ensure our tables & indexes exist (without crashing on dup–index)
init_db()

sched = BackgroundScheduler()
sched.add_job(
    func=sync_events_job,
    trigger='interval',
    hours=24,
    next_run_time=datetime.utcnow() + timedelta(seconds=10)   # 2. give DB time
)                                                             #    to be created
sched.start()

# Main Execution
# ----------------------------

if __name__ == "__main__":
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000)
