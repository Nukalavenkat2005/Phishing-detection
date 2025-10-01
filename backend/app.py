import os
import re
import html
import torch
import base64
from flask import Flask, request, jsonify
from flask_cors import CORS
from transformers import BertTokenizer, BertForSequenceClassification

# Gmail API imports
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# ---------------------------
# Flask app
# ---------------------------
app = Flask(__name__)
CORS(app)

# ---------------------------
# Load BERT Model
# ---------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "final_model")

tokenizer = BertTokenizer.from_pretrained(MODEL_PATH, local_files_only=True)
bert_model = BertForSequenceClassification.from_pretrained(MODEL_PATH, local_files_only=True)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
bert_model.to(device)
bert_model.eval()

LABEL_MAP = {0: "Legitimate", 1: "Phishing"}

# ---------------------------
# Gmail Setup
# ---------------------------
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
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

# ---------------------------
# Prediction Helpers
# ---------------------------
def predict_body(text):
    """Classify email body using fine-tuned BERT"""
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=512)
    inputs = {k: v.to(device) for k, v in inputs.items()}

    with torch.no_grad():
        outputs = bert_model(**inputs)
        probs = torch.softmax(outputs.logits, dim=1).cpu().numpy()[0]

    pred_idx = int(probs.argmax())
    label = LABEL_MAP[pred_idx]
    confidence = round(float(probs[pred_idx]) * 100, 2)
    return {"prediction": label, "confidence": confidence}

def analyze_sender(headers):
    """Rule-based sender/domain analysis"""
    sender = next((h["value"] for h in headers if h["name"].lower() == "from"), "")
    match = re.search(r"<(.+?)>", sender)
    email = match.group(1) if match else sender
    domain = email.split("@")[-1].lower() if "@" in email else "unknown"

    flags = []

    # Rule 1: Typosquatting keywords
    if re.search(r"(paypa1|netfl1x|g00gle|faceb00k)", domain):
        flags.append("Possible typosquatting")

    # Rule 2: Suspicious TLDs
    if domain.split(".")[-1] in ["xyz", "top", "ru", "cn"]:
        flags.append("Suspicious TLD")

    # Rule 3: Too many subdomains
    if domain.count(".") > 3:
        flags.append("Too many subdomains")

    # Rule 4: Whitelist
    whitelist = ["google.com", "microsoft.com", "github.com", "apple.com", "linkedin.com"]
    if domain in whitelist:
        flags.append("✅ Whitelisted domain")

    return {"sender": email, "domain": domain, "flags": flags if flags else ["None"]}

def extract_body(payload):
    """Extract full plain-text body from Gmail payload"""
    if "parts" in payload:
        for part in payload["parts"]:
            if part["mimeType"] == "text/plain":
                data = part["body"].get("data", "")
                return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
    if "body" in payload and "data" in payload["body"]:
        return base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8", errors="ignore")
    return ""

# ---------------------------
# Routes
# ---------------------------
@app.route("/")
def home():
    return "🚀 Phishing Email Detection API is Running"

@app.route("/predict", methods=["POST"])
def predict():
    """Manual email body check"""
    data = request.get_json()
    if not data or "text" not in data:
        return jsonify({"error": "No text provided"}), 400

    text = data["text"]
    body_result = predict_body(text)
    return jsonify(body_result)

@app.route("/fetch_gmail", methods=["GET"])
def fetch_gmail():
    """Fetch latest unread email from Gmail"""
    try:
        service = get_gmail_service()
        results = service.users().messages().list(userId="me", labelIds=["UNREAD"], maxResults=1).execute()
        messages = results.get("messages", [])

        if not messages:
            return jsonify({"error": "No unread emails found"}), 404

        msg_id = messages[0]["id"]
        msg = service.users().messages().get(userId="me", id=msg_id, format="full").execute()

        snippet = msg.get("snippet", "")
        headers = msg["payload"].get("headers", [])
        body_text = extract_body(msg.get("payload", {}))

        # Run predictions
        sender_info = analyze_sender(headers)
        body_result = predict_body(body_text if body_text else snippet)

        return jsonify({
            "email_snippet": html.unescape(snippet)[:80] + "...",  # Preview only
            "body_prediction": body_result,
            "sender_info": sender_info
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------------------
# Run server
# ---------------------------
if __name__ == "__main__":
    app.run(debug=True)
