"""
demo/vulnerable_function.py
Demonstrates an insecure serverless function containing hardcoded credentials.
NOTE: All credentials below are fake dummy values used strictly for testing.
"""

import json

# INSECURE PRACTICE: Hardcoding sensitive credentials directly in source files
API_KEY = "test123"
PASSWORD = "mypassword"
AWS_SECRET_ACCESS_KEY = "example"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AUTH_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy_token_payload"


def lambda_handler(event, context):
    """
    AWS Lambda entry point containing vulnerable static secret references.
    """
    # Using hardcoded API key in outbound request
    headers = {
        "Authorization": f"Bearer {AUTH_TOKEN}",
        "X-Api-Key": API_KEY
    }

    print(f"Connecting to database using password: {PASSWORD}")
    print(f"Using AWS Secret Access Key: {AWS_SECRET_ACCESS_KEY}")

    return {
        "statusCode": 200,
        "body": json.dumps({"status": "vulnerable function executed"})
    }
