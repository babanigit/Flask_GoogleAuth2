from flask import Flask, json, redirect, url_for, session, request, jsonify
from requests_oauthlib import OAuth2Session
import os
import requests
from flask_cors import CORS
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload


# Flask app initialization
app = Flask(__name__)

# Configure CORS more comprehensively
CORS(
    app,
    resources={
        r"/*": {
            "origins": ["http://localhost:5173", "http://127.0.0.1:5173"],
            "supports_credentials": True,
            "allow_headers": ["Content-Type", "Authorization"],
            "methods": ["GET", "POST", "OPTIONS"],
        }
    },
)

# Set a secret key
app.secret_key = os.urandom(24)  # Generates a random 24-byte key

# Allow insecure transport for development (HTTP)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# Load credentials.json
with open("credentials.json", "r") as file:
    credentials = json.load(file)["web"]

CLIENT_ID = credentials["client_id"]
CLIENT_SECRET = credentials["client_secret"]
REDIRECT_URI = credentials["redirect_uris"][0]  # Access the first redirect URI
AUTH_URI = credentials["auth_uri"]
TOKEN_URI = credentials["token_uri"]

# Define scopes
SCOPES = [
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/drive.file",  # Google Drive scope
]


@app.route("/")
def index():
    return 'Welcome to the Google OAuth 2.0 example! <a href="/login">Login with Google</a>'


@app.route("/login")
def login():
    # Create an OAuth2Session instance
    google = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, scope=SCOPES)

    # Get the authorization URL
    authorization_url, state = google.authorization_url(
        AUTH_URI, access_type="offline", prompt="consent"
    )

    # Save the state to the session for security
    session["oauth_state"] = state

    return redirect(authorization_url)


@app.route("/login/google/authorized")
def callback():
    # Retrieve the state from the session
    state = session.get("oauth_state")

    # Create an OAuth2Session instance with the state
    google = OAuth2Session(CLIENT_ID, state=state, redirect_uri=REDIRECT_URI)

    # Fetch the token using the authorization response URL
    token = google.fetch_token(
        TOKEN_URI, client_secret=CLIENT_SECRET, authorization_response=request.url
    )

    # Store token in the session
    session["oauth_token"] = token

    # Redirect back to React app with access token
    redirect_url = f"http://localhost:5173/?access_token={token['access_token']}"
    return redirect(redirect_url)

@app.route("/upload", methods=["POST"])
def upload_file():
    # Check if the user is authenticated
    if "oauth_token" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    # Get the uploaded file
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    try:
        # Create Google Drive service
        credentials = Credentials(
            token=session["oauth_token"]["access_token"],
            refresh_token=session["oauth_token"].get("refresh_token"),
            token_uri=TOKEN_URI,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
        )

        service = build("drive", "v3", credentials=credentials)

        # Upload file to Google Drive
        file_metadata = {"name": file.filename}
        media = MediaFileUpload(file, resumable=True)

        file_obj = (
            service.files()
            .create(body=file_metadata, media_body=media, fields="id")
            .execute()
        )

        return (
            jsonify(
                {"message": "File uploaded successfully", "file_id": file_obj.get("id")}
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/logout")
def logout():
    session.pop("oauth_token", None)
    return redirect(url_for("index"))


@app.route("/options", methods=["OPTIONS"])
def options_handler():
    response = jsonify(success=True)
    response.headers.add("Access-Control-Allow-Origin", "http://localhost:5173")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization")
    response.headers.add("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
    response.headers.add("Access-Control-Allow-Credentials", "true")
    return response


if __name__ == "__main__":
    app.run(debug=True)
