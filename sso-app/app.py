from flask import Flask, redirect, url_for, session, render_template, request
from authlib.integrations.flask_client import OAuth
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# OAuth 2 client setup
oauth = OAuth(app)

# Keycloak configuration
KEYCLOAK_REALM = 'federated-idp'
KEYCLOAK_CLIENT_ID = 'sso-app'
KEYCLOAK_CLIENT_SECRET = os.environ.get('KEYCLOAK_CLIENT_SECRET', 'your-client-secret')

# For browser redirects, we use the public URL (localhost)
KEYCLOAK_PUBLIC_URL = os.environ.get('KEYCLOAK_PUBLIC_URL', 'http://localhost:8080/auth')
# For direct, server-to-server communication from within the container, we use the internal service name
KEYCLOAK_INTERNAL_URL = os.environ.get('KEYCLOAK_INTERNAL_URL', 'http://keycloak:8080/auth')

REALM_PATH = f"realms/{KEYCLOAK_REALM}"

import requests

app = Flask(__name__)
app.secret_key = os.urandom(24)

# OAuth 2 client setup
oauth = OAuth(app)

# Keycloak configuration
KEYCLOAK_REALM = 'federated-idp'
KEYCLOAK_CLIENT_ID = 'sso-app'
KEYCLOAK_CLIENT_SECRET = os.environ.get('KEYCLOAK_CLIENT_SECRET', 'your-client-secret')

KEYCLOAK_PUBLIC_URL = os.environ.get('KEYCLOAK_PUBLIC_URL', 'http://localhost:8080/auth')
KEYCLOAK_INTERNAL_URL = os.environ.get('KEYCLOAK_INTERNAL_URL', 'http://keycloak:8080/auth')

# Fetch the discovery document
discovery_url = f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration"
resp = requests.get(discovery_url)
resp.raise_for_status()
server_metadata = resp.json()

# Replace internal URLs with public URLs for browser-facing endpoints
public_endpoints = ['authorization_endpoint', 'end_session_endpoint']
for endpoint in public_endpoints:
    if endpoint in server_metadata:
        server_metadata[endpoint] = server_metadata[endpoint].replace(KEYCLOAK_INTERNAL_URL, KEYCLOAK_PUBLIC_URL)

oauth.register(
    name='keycloak',
    client_id=KEYCLOAK_CLIENT_ID,
    client_secret=KEYCLOAK_CLIENT_SECRET,
    server_metadata_url=f'{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid profile email'
    }
)

# Override the fetched metadata with our corrected version
oauth.keycloak.server_metadata = server_metadata



@app.route('/')
def index():
    """Home page, shows login link or user info."""
    user = session.get('user')
    return render_template('index.html', user=user)

@app.route('/login')
def login():
    """Redirects to Keycloak login page."""
    redirect_uri = url_for('auth', _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)

@app.route('/auth')
def auth():
    """Callback route for Keycloak."""
    token = oauth.keycloak.authorize_access_token()
    userinfo = oauth.keycloak.parse_id_token(token)
    session['user'] = userinfo
    return redirect(url_for('profile'))

@app.route('/profile')
def profile():
    """Displays user profile information."""
    user = session.get('user')
    if not user:
        return redirect(url_for('index'))
    
    return render_template('profile.html', user=user)


@app.route('/logout')
def logout():
    """Logs the user out."""
    session.pop('user', None)
    keycloak_logout_url = server_metadata.get('end_session_endpoint')
    if keycloak_logout_url:
        post_logout_redirect_uri = url_for('index', _external=True)
        return redirect(f'{keycloak_logout_url}?post_logout_redirect_uri={post_logout_redirect_uri}&client_id={KEYCLOAK_CLIENT_ID}')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)