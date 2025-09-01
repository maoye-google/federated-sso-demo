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

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle login with automatic domain detection."""
    if request.method == 'GET':
        # Show custom login form
        return render_template('login.html')
    
    elif request.method == 'POST':
        username = request.form.get('username', '').strip()
        if not username:
            return render_template('login.html', error='Please enter your username/email')
        
        # Detect domain from username
        if '@' in username:
            domain = username.split('@')[1].lower()
            if domain == 'domain-1.com':
                idp_hint = 'domain-1-idp'
            elif domain == 'domain-2.com':
                idp_hint = 'domain-2-idp'
            else:
                idp_hint = 'domain-1-idp'  # Default fallback
        else:
            idp_hint = 'domain-1-idp'  # Default for usernames without domain
        
        # Store username in session for later use
        session['login_hint'] = username
        
        # Store the detected IDP for the OAuth flow
        session['detected_idp'] = idp_hint
        
        # Manual OAuth authorization URL construction to avoid state issues
        redirect_uri = url_for('auth', _external=True)
        
        # Construct authorization URL manually without Authlib state management
        auth_params = {
            'client_id': KEYCLOAK_CLIENT_ID,
            'response_type': 'code',
            'redirect_uri': redirect_uri,
            'scope': 'openid profile email',
            'kc_idp_hint': idp_hint,
            'login_hint': username
        }
        
        # Build query string
        from urllib.parse import urlencode
        auth_url = f"{KEYCLOAK_PUBLIC_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth?{urlencode(auth_params)}"
        
        app.logger.info(f"Redirecting to manual auth URL: {auth_url}")
        return redirect(auth_url)

@app.route('/auth')
def auth():
    """Callback route for Keycloak."""
    # Check if we have an authorization code from the OAuth flow
    code = request.args.get('code')
    error = request.args.get('error')
    
    if error:
        return f"Authentication failed: {error}", 400
    
    if not code:
        return "Authentication failed: No authorization code received", 400
    
    try:
        # Always use manual token exchange for federated flows to avoid state issues
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': url_for('auth', _external=True),
            'client_id': KEYCLOAK_CLIENT_ID,
            'client_secret': KEYCLOAK_CLIENT_SECRET
        }
        
        token_url = f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
        app.logger.info(f"Exchanging token at: {token_url}")
        
        token_response = requests.post(token_url, data=token_data)
        token_response.raise_for_status()
        token = token_response.json()
        
        app.logger.info(f"Token exchange successful, token keys: {token.keys()}")
        
        # Extract user info from ID token
        if 'id_token' in token:
            import jwt
            # Decode without verification since it's from our trusted Keycloak
            userinfo = jwt.decode(token['id_token'], options={"verify_signature": False})
            app.logger.info(f"User info extracted: {userinfo.get('preferred_username', 'unknown')}")
        else:
            return "Authentication failed: No ID token in response", 500
        
        # Store user information in session
        session['user'] = userinfo
        return redirect(url_for('profile'))
        
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Token exchange failed: {e}")
        return f"Authentication failed: Token exchange error - {str(e)}", 500
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
    """Logs the user out and clears all session data including domain IDP sessions."""
    # Clear all session data
    session.clear()
    
    # Direct redirect to Keycloak federated logout with proper parameters
    keycloak_logout_url = f"{KEYCLOAK_PUBLIC_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/logout"
    post_logout_redirect_uri = url_for('logout_complete', _external=True)
    
    # Use Keycloak's built-in logout mechanism with post-logout redirect
    logout_url = f'{keycloak_logout_url}?post_logout_redirect_uri={post_logout_redirect_uri}&client_id={KEYCLOAK_CLIENT_ID}'
    return redirect(logout_url)

@app.route('/logout-complete')
def logout_complete():
    """Complete logout process and clear any remaining sessions."""
    # Ensure session is completely cleared
    session.clear()
    
    # Create a page that clears browser storage and redirects
    logout_complete_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Logout Complete</title>
        <meta http-equiv="refresh" content="2;url={url_for('index', _external=True)}">
    </head>
    <body>
        <p>Logout complete. Redirecting...</p>
        <script>
            // Clear any stored authentication data
            localStorage.clear();
            sessionStorage.clear();
            
            // Clear cookies by setting them to expire
            document.cookie.split(";").forEach(function(c) {{ 
                document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/"); 
            }});
            
            // Redirect immediately
            setTimeout(function() {{
                window.location.href = '{url_for('index', _external=True)}';
            }}, 1000);
        </script>
    </body>
    </html>
    """
    
    return logout_complete_html

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)