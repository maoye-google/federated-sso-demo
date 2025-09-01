from flask import Flask, redirect, url_for, session, render_template, request
from authlib.integrations.flask_client import OAuth
import os
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

def get_oauth_client():
    """Lazy-load OAuth client configuration when needed."""
    
    if not hasattr(oauth, 'keycloak'):
        # Direct configuration without discovery document
        oauth.register(
            name='keycloak',
            client_id=KEYCLOAK_CLIENT_ID,
            client_secret=KEYCLOAK_CLIENT_SECRET,
            authorize_url=f"{KEYCLOAK_PUBLIC_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth",
            access_token_url=f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
            userinfo_endpoint=f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/userinfo",
            jwks_uri=f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs",
            client_kwargs={
                'scope': 'openid profile email'
            }
        )
        print(f"DEBUG: Direct OAuth configuration complete")
        print(f"DEBUG: authorize_url: {KEYCLOAK_PUBLIC_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth")
        print(f"DEBUG: access_token_url: {KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token")
                    
    return oauth.keycloak



@app.route('/')
def index():
    """Home page, shows login link or user info."""
    user = session.get('user')
    return render_template('index.html', user=user)

@app.route('/login')
def login():
    """Redirects to Keycloak login page."""
    redirect_uri = url_for('auth', _external=True)
    return get_oauth_client().authorize_redirect(redirect_uri)

@app.route('/auth')
def auth():
    """Callback route for Keycloak."""
    try:
        keycloak_client = get_oauth_client()
        token = keycloak_client.authorize_access_token()
        # Parse ID token with nonce validation
        userinfo = keycloak_client.parse_id_token(token, nonce=session.get('_oauth_nonce'))
        session['user'] = userinfo
        return redirect(url_for('profile'))
    except Exception as e:
        app.logger.error(f"OAuth callback error: {e}")
        return f"Authentication failed: {str(e)}", 500

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
    # Get server metadata for logout endpoint
    keycloak_client = get_oauth_client()
    server_metadata = keycloak_client.server_metadata
    keycloak_logout_url = server_metadata.get('end_session_endpoint')
    if keycloak_logout_url:
        post_logout_redirect_uri = url_for('index', _external=True)
        return redirect(f'{keycloak_logout_url}?post_logout_redirect_uri={post_logout_redirect_uri}&client_id={KEYCLOAK_CLIENT_ID}')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)