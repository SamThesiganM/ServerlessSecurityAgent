"""
demo/safe_function.py
Demonstrates a secure serverless function adhering to best practices:
- Retrieves configuration and secrets from environment variables or a secrets manager.
- Never hardcodes passwords, API keys, or cloud credentials.
"""

import json
import os
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# SECURE PRACTICE: Retrieve credentials dynamically from environment variables
# In production, these are injected by AWS Lambda environment configuration or AWS Secrets Manager.
DATABASE_URL = os.environ.get("DATABASE_URL")
SERVICE_API_KEY = os.environ.get("THIRD_PARTY_API_KEY")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")


def lambda_handler(event, context):
    """
    AWS Lambda entry point.
    Safely processes incoming event without exposing sensitive credentials.
    """
    logger.info("Processing request...")

    # Ensure required configuration is present at runtime
    if not DATABASE_URL or not SERVICE_API_KEY:
        logger.error("Missing required environment configuration.")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Service configuration incomplete"})
        }

    # Simulate business logic
    user_id = event.get("userId", "anonymous")
    logger.info(f"Successfully processed request for user: {user_id}")

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "Operation completed securely",
            "userId": user_id
        })
    }
