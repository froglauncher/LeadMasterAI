import os
import json
import base64
import logging
import traceback
from datetime import timedelta, datetime

from flask import Flask, request, redirect, session, url_for
from flask_session import Session
from dotenv import load_dotenv
from google.cloud import secretmanager
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import google.auth.transport.requests

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

from email.mime.text import MIMEText
from google.oauth2 import service_account

from ratelimit import limits, sleep_and_retry

# ======================
# Setup Logging
# ======================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ======================
# Load environment variables
# ======================
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-here')

# Configure server-side session
app.config.update(
    SESSION_TYPE='filesystem',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=30)
)
Session(app)

# OAuth 2.0 configuration
SCOPES = [
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/gmail.send'
]

CLAUDE_API_KEY = os.getenv('CLAUDE_API_KEY')
if not CLAUDE_API_KEY:
    logger.error("CLAUDE_API_KEY is not set. Please set the environment variable.")
    raise EnvironmentError("CLAUDE_API_KEY not found")

def load_credentials_file():
    """Load the client secret file from disk."""
    client_secrets_file = os.path.join(os.getcwd(), 'client_secret.json')
    if not os.path.exists(client_secrets_file):
        logger.error("client_secret.json is missing! Download it from Google Cloud Console")
        raise FileNotFoundError('client_secret.json is missing!')
    return client_secrets_file

def get_gmail_service():
    """Get Gmail service using OAuth2 credentials."""
    try:
        logger.info("Getting Gmail service using OAuth2...")
        
        # Try to load credentials from Secret Manager
        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/leadmasterai/secrets/gmail_credentials/versions/latest"
        response = client.access_secret_version(request={"name": name})
        credentials_data = json.loads(response.payload.data.decode("UTF-8"))
        
        # Create credentials object
        credentials = Credentials(
            token=credentials_data.get('token'),
            refresh_token=credentials_data.get('refresh_token'),
            token_uri=credentials_data.get('token_uri', 'https://oauth2.googleapis.com/token'),
            client_id=credentials_data.get('client_id'),
            client_secret=credentials_data.get('client_secret'),
            scopes=credentials_data.get('scopes', SCOPES)
        )

        # If token is expired or about to expire, refresh it
        if not credentials.valid or credentials.expired:
            logger.info("Token expired or invalid, refreshing...")
            request = google.auth.transport.requests.Request()
            credentials.refresh(request)
            
            # Update credentials in Secret Manager
            credentials_data.update({
                'token': credentials.token,
                'refresh_token': credentials.refresh_token,
            })
            
            secret_data = json.dumps(credentials_data)
            client.add_secret_version(
                request={
                    "parent": "projects/leadmasterai/secrets/gmail_credentials",
                    "payload": {"data": secret_data.encode("UTF-8")}
                }
            )
            logger.info("Credentials refreshed and updated in Secret Manager")

        service = build('gmail', 'v1', credentials=credentials)
        logger.info("Successfully created Gmail service")
        return service

    except Exception as e:
        logger.error(f"Error getting Gmail service: {str(e)}\n{traceback.format_exc()}")
        # If we get a specific OAuth error, we need to reauthorize
        if 'invalid_grant' in str(e):
            logger.error("Invalid grant error - need to reauthorize")
            return None
        return None

def format_phone_number(phone):
    """Format phone number to (XXX) XXX-XXXX if 10 digits."""
    digits = ''.join(filter(str.isdigit, phone))
    if len(digits) == 10:
        return f"({digits[:3]}) {digits[3:6]}-{digits[6:]}"
    return phone

def format_address(street, city, state, zip_code):
    """
    Format address with proper capitalization.
    State should remain uppercase.
    """
    if not (street or city or state or zip_code):
        return ""
    words = street.split()
    formatted_words = []
    for w in words:
        if w.lower() in ['n', 's', 'e', 'w']:
            formatted_words.append(w.upper())
        else:
            formatted_words.append(w.title())
    formatted_street = ' '.join(formatted_words)
    city = city.title() if city else ""
    state = state.upper() if state else ""
    return f"{formatted_street}, {city}, {state} {zip_code}".strip()

def process_lead_email(message):
    """Extract and format lead information using Claude AI with improved prompt."""

    try:
        # Extract the email body
        if 'payload' not in message:
            logger.error("Message payload not found in Gmail message.")
            return "Could not process email content", {}

        payload = message['payload']
        parts = payload.get('parts', [])
        body = ""
        for part in parts:
            if part.get('mimeType') == 'text/plain' and 'data' in part.get('body', {}):
                body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                break

        if not body:
            logger.warning("No text/plain part found in email message.")
            return "Could not process email content", {}

        logger.info("Processing email body with Claude API")

        # Improved prompt:
        # - Instruct to ignore signatures, disclaimers, and footers.
        # - Emphasize to only focus on the actual lead information.
        # - State that the lead info should be in the main body, not from the sender or footer.
        prompt = f"""
        The following is an email lead. You need to extract the lead's key details only from the main content of the email. Ignore any email signature, disclaimer, or company boilerplate found at the bottom of the email. If multiple sets of contact info appear, choose the one that corresponds to the lead (not the sender's signature). Do not use the 'From' field or signatures as the data source.

        Extract this information and return as JSON:
        {body}

        Required JSON format strictly:
        {{
            "first_name": "First name of the lead (properly capitalized)",
            "last_name": "Last name of the lead (properly capitalized)",
            "company": "Business name",
            "street": "Street address with proper caps",
            "city": "City name",
            "state": "STATE in uppercase",
            "zip": "Five digit ZIP",
            "phone": "(XXX) XXX-XXXX",
            "email": "email@example.com",
            "property_type": "Commercial or Residential",
            "service_needed": "Type of service requested",
            "notes": "Additional details about the request"
        }}

        Important instructions:
        - Do not include email signatures, disclaimers, or footer information commonly found at the bottom.
        - If unsure about a piece of data (e.g., a phone number that appears in the signature only), do not guess. Return it as an empty string.
        - The email is from a potential lead requesting a service. Focus on their request, their contact info, and their company details from the main text, not from any appended signature or template.
        """

        # Set up requests session with retries
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        headers = {
            "x-api-key": CLAUDE_API_KEY,
            "content-type": "application/json",
            "anthropic-version": "2023-06-01"
        }

        data = {
            "model": "claude-3-haiku-20240307",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}]
        }

        try:
            response = session.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json=data,
                timeout=30
            )
        except requests.exceptions.RequestException:
            logger.error("Error calling Claude API: %s", traceback.format_exc())
            return f"Error processing lead with Claude:<br><br>Original email:<br>{body}", {}

        logger.info("Claude API response status: %s", response.status_code)
        logger.debug("Claude API response: %s", response.text)

        if response.status_code != 200:
            logger.error("Claude API error: %s", response.text)
            return f"Error processing lead with Claude: {response.text}<br><br>Original email:<br>{body}", {}

        response_data = response.json()
        content_list = response_data.get('content', [])
        if not content_list or not isinstance(content_list, list):
            logger.error("Claude API response missing expected 'content' structure.")
            return f"Error processing lead with Claude: Invalid response format<br><br>Original email:<br>{body}", {}

        lead_text = content_list[0].get('text', '{}')
        try:
            lead_info = json.loads(lead_text)
        except json.JSONDecodeError:
            logger.error("Failed to parse JSON from Claude response.")
            return f"Error processing lead with Claude: Could not decode JSON<br><br>Original email:<br>{body}", {}

        logger.info("Parsed lead info successfully: %s", lead_info)

        # Extract fields from lead_info
        first_name = lead_info.get("first_name", "")
        last_name = lead_info.get("last_name", "")
        contact_name = f"{first_name} {last_name}".strip()
        business_name = lead_info.get("company", "")
        street = lead_info.get("street", "")
        city = lead_info.get("city", "")
        state = lead_info.get("state", "")
        zip_code = lead_info.get("zip", "")
        phone_number = lead_info.get("phone", "")
        email_address = lead_info.get("email", "")
        address_analysis = lead_info.get("property_type", "")
        reason_for_service = lead_info.get("service_needed", "")
        additional_info = lead_info.get("notes", "")

        formatted_phone = format_phone_number(phone_number)
        formatted_address = format_address(street, city, state, zip_code)

        formatted_lead = f"""
        <div style="font-family: Arial, sans-serif; line-height: 1.6;">
            <h2>Lead Information Summary</h2>

            <strong>Contact Details:</strong><br>
            • Name: {contact_name}<br>
            • Company: {business_name}<br><br>

            <strong>Contact Information:</strong><br>
            • Phone: <a href="tel:{formatted_phone}">{formatted_phone}</a><br>
            • Email: <a href="mailto:{email_address}">{email_address}</a><br><br>

            <strong>Location:</strong><br>
            • Address: {formatted_address}<br>
            • Navigation: (<a href="https://www.google.com/maps/search/?api=1&query={requests.utils.quote(formatted_address)}">Google Maps</a> | 
               <a href="http://maps.apple.com/?q={requests.utils.quote(formatted_address)}">Apple Maps</a> | 
               <a href="https://waze.com/ul?q={requests.utils.quote(formatted_address)}">Waze</a>)<br><br>

            <strong>Property Details:</strong><br>
            • Type: {address_analysis}<br>
            • Service Needed: {reason_for_service}<br><br>

            <strong>Additional Information:</strong><br>
            {additional_info}<br><br>

            If any of this information needs correction, please let us know.<br><br>

            Best regards,<br>
            LeadMaster AI
        </div>
        """

        return formatted_lead, lead_info

    except Exception:
        logger.error("Unexpected error: %s", traceback.format_exc())
        return "Error processing lead", {"error": "Unexpected error"}

def send_response(service, to, subject, message_text, crm_data):
    """Send an email response with structured CRM data."""
    message = MIMEText(message_text, 'html')
    message['to'] = to
    message['from'] = 'leadmasterai@gmail.com'
    message['subject'] = subject
    # Add structured data for CRM ingestion
    message['X-OnePageCRM-Data'] = json.dumps(crm_data)

    raw = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
    try:
        service.users().messages().send(
            userId='me',
            body={'raw': raw}
        ).execute()
        return True
    except Exception:
        logger.error("Error sending email: %s", traceback.format_exc())
        return False

def process_unread_emails():
    """Process new unread emails immediately."""
    service = get_gmail_service()
    if not service:
        logger.warning("Gmail service not available")
        return "Service not available"

    try:
        # Change to 3 minutes to match scheduler interval
        three_minutes_ago = int((datetime.now() - timedelta(minutes=3)).timestamp())
        results = service.users().messages().list(
            userId='me',
            q=f'is:unread after:{three_minutes_ago}'  # Match scheduler interval
        ).execute()
        
        messages = results.get('messages', [])
        if not messages:
            logger.info("No new emails to process")
            return "No new emails to process"

        processed_count = 0
        for message in messages:
            try:
                msg = service.users().messages().get(
                    userId='me',
                    id=message['id']
                ).execute()

                # Process immediately
                headers = msg['payload']['headers']
                from_email = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
                formatted_lead, lead_info = process_lead_email(msg)
                
                if send_response(
                    service=service,
                    to=from_email,
                    subject='Re: Lead Information Processed',
                    message_text=formatted_lead,
                    crm_data=lead_info
                ):
                    # Mark as read immediately after processing
                    service.users().messages().modify(
                        userId='me',
                        id=message['id'],
                        body={'removeLabelIds': ['UNREAD']}
                    ).execute()
                    processed_count += 1
                    logger.info(f"Processed email from {from_email} within {datetime.now().timestamp() - three_minutes_ago} seconds")

            except Exception as e:
                logger.error(f"Error processing individual message: {str(e)}")
                continue

        return f"Processed {processed_count} emails successfully"

    except Exception as e:
        logger.error(f"Error in process_unread_emails: {str(e)}")
        return f"Error processing emails: {str(e)}"

@app.route('/')
def index():
    if 'credentials' in session:
        return '''
            <h1>Connected to Gmail!</h1>
            <p><a href="/test_gmail">Test Gmail Connection</a></p>
            <p><a href="/process_emails">Process New Emails</a></p>
            <p><a href="/logout">Logout</a></p>
        '''
    return '<a href="/authorize">Click here to authorize Gmail access</a>'

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/authorize')
def authorize():
    state = os.urandom(16).hex()
    session['state'] = state

    flow = Flow.from_client_secrets_file(
        load_credentials_file(),
        scopes=SCOPES,
        state=state,
        redirect_uri='https://email-processor-19123906855.us-east1.run.app/oauth2callback'
    )
    authorization_url, _ = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    try:
        if 'state' not in session:
            logger.error("No state found in session")
            return 'Error: Session state not found', 400

        state = session['state']
        flow = Flow.from_client_secrets_file(
            load_credentials_file(),
            scopes=SCOPES,
            state=state,
            redirect_uri='https://email-processor-19123906855.us-east1.run.app/oauth2callback'
        )

        authorization_response = 'https://' + request.host + request.full_path
        flow.fetch_token(authorization_response=authorization_response)
        credentials = flow.credentials

        # Store credentials in Secret Manager
        gmail_credentials = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }

        client = secretmanager.SecretManagerServiceClient()
        secret_data = json.dumps(gmail_credentials)
        client.add_secret_version(
            request={
                "parent": "projects/leadmasterai/secrets/gmail_credentials",
                "payload": {"data": secret_data.encode("UTF-8")}
            }
        )

        session['credentials'] = True
        logger.info("Authorization successful, credentials stored in Secret Manager.")
        return 'Authorization successful! You can now close this window.'
    except Exception as e:
        logger.error("Error during OAuth callback: %s", traceback.format_exc())
        return f"Error during OAuth callback: {str(e)}"

@app.route('/test_gmail')
def test_gmail():
    service = get_gmail_service()
    if not service:
        return redirect(url_for('authorize'))

    try:
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])
        return f'Connected successfully! Found {len(labels)} labels in Gmail.'
    except Exception:
        logger.error("Error testing Gmail: %s", traceback.format_exc())
        return "Error testing Gmail connection."

@app.route('/process_emails')
def process_emails():
    result = process_unread_emails()
    return result

ONE_MINUTE = 60
MAX_CALLS_PER_MINUTE = 60

@sleep_and_retry
@limits(calls=MAX_CALLS_PER_MINUTE, period=ONE_MINUTE)
def rate_limited_api_call(service_func, *args, **kwargs):
    return service_func(*args, **kwargs)

if __name__ == '__main__':
    # Do not run the Flask dev server for production.
    # Instead, rely on Gunicorn via Dockerfile CMD.
    # For local testing only:
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
