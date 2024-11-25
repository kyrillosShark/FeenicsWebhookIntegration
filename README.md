# README

## Overview

This project is a Flask-based web application designed to integrate with Keep by Feenics, a cloud-based access control system. It includes functionality for user management, badge and card format handling, and access level assignments. Additionally, it provides a mechanism for simulating card reads to unlock doors and other access-controlled operations.

## Features

- **User Management**: Create, update, and extend user memberships.
- **Access Control Integration**: Interact with Keep by Feenics API for managing badges, cards, access levels, and readers.
- **Unlock Mechanism**: Generate and validate unlock tokens and simulate card reads.
- **Webhook Support**: Handle external requests to create or update user data.
- **Geofencing**: Validate user proximity to the gym before granting access.
- **Database Integration**: Uses SQLAlchemy with Flask-Migrate for database operations.
- **Resilient API Requests**: Implements retry logic for API requests using `requests` with retry and backoff mechanisms.
- **Twilio Integration**: (Optional) Send SMS notifications using Twilio.

## Requirements

### Environment Variables

The application requires the following environment variables:

- **Core Configuration**:
  - `BASE_ADDRESS`: API base URL for Keep by Feenics.
  - `INSTANCE_NAME`: Name of the Keep by Feenics instance.
  - `KEEP_USERNAME` / `KEEP_PASSWORD`: Authentication credentials.
  - `DATABASE_URL`: SQLAlchemy-compatible database URI.
- **Badge/Card Configuration**:
  - `BADGE_TYPE_NAME`: Default badge type name (default: "Employee Badge").
  - `FACILITY_CODE`: Facility code for card number generation.
- **Unlock Link**:
  - `UNLOCK_LINK_BASE_URL`: Base URL for generating unlock links.
- **Twilio (Optional)**:
  - `TWILIO_ACCOUNT_SID` / `TWILIO_AUTH_TOKEN`: Twilio credentials.
  - `TWILIO_PHONE_NUMBER`: Twilio phone number for sending SMS.
- **Token Validity**:
  - `TOKEN_VALIDITY_HOURS`: (Optional) Hours for which the unlock token is valid (default: 24).

### Python Dependencies

Install the required dependencies using `pip`:

```bash
pip install -r requirements.txt


