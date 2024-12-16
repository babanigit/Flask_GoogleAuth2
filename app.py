from flask import Flask, json, redirect, url_for, session, request
from requests_oauthlib import OAuth2Session
import os

# Flask app initialization
app = Flask(__name__)

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

    # Store token in the session (you can also save it securely in a database)
    session["oauth_token"] = token

    return f"Access Token: {token['access_token']}<br>Refresh Token: {token.get('refresh_token', 'No refresh token provided')}"


@app.route("/logout")
def logout():
    session.pop("oauth_token", None)
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
