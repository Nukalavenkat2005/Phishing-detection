import os
import base64
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]  # ✅ allows marking as read
TOKEN_PATH = "token.json"
CREDS_PATH = "credentials.json"

def get_gmail_service():
    creds = None
    if os.path.exists(TOKEN_PATH):
        creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file(CREDS_PATH, SCOPES)
        creds = flow.run_local_server(port=0)
        with open(TOKEN_PATH, "w") as token:
            token.write(creds.to_json())
    return build("gmail", "v1", credentials=creds)

def fetch_latest_email_text(n=1):
    service = get_gmail_service()
    results = service.users().messages().list(
        userId="me", labelIds=["UNREAD"], maxResults=n
    ).execute()
    messages = results.get("messages", [])

    email_texts = []
    for msg in messages:
        msg_id = msg["id"]
        full_msg = service.users().messages().get(
            userId="me", id=msg_id, format="full"
        ).execute()
        payload = full_msg.get("payload", {})

        def get_body(payload):
            if "parts" in payload:
                for part in payload["parts"]:
                    if part["mimeType"] == "text/plain":
                        return base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8", errors="ignore")
            if "body" in payload and "data" in payload["body"]:
                return base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8", errors="ignore")
            return ""

        body = get_body(payload)
        email_texts.append(body if body else full_msg.get("snippet", ""))

        # ✅ Mark as read so it won’t repeat next time
        service.users().messages().modify(
            userId="me", id=msg_id, body={"removeLabelIds": ["UNREAD"]}
        ).execute()

    return email_texts
