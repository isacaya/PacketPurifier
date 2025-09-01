from flask import Flask, request, make_response
import time
from datetime import datetime
import random
import string

app = Flask(__name__)

def generate_validation_token():
    length = random.randint(16, 64)
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

@app.route('/test', methods=['GET'])
def test_endpoint():
    # Simulate a slight processing delay
    time.sleep(0.1)
    
    # Get headers
    user_agent = request.headers.get('User-Agent')
    custom_header = request.headers.get('Custom-Header')
    
    # Get query parameters
    id_param = request.args.get('id')
    track_param = request.args.get('track')
    
    # Essential header check: User-Agent
    if not user_agent:
        return """
        <html>
            <head><title>400 Bad Request</title></head>
            <body>
                <h1>400 Bad Request</h1>
                <p>User-Agent header is required</p>
            </body>
        </html>
        """, 400
    
    # Essential query param check: id
    if not id_param:
        return """
        <html>
            <head><title>400 Bad Request</title></head>
            <body>
                <h1>400 Bad Request</h1>
                <p>id query parameter is required</p>
            </body>
        </html>
        """, 400
    
    # Get cookie2 value (if present)
    cookie2_value = request.cookies.get('cookie2')
    
    # Build HTML response
    message = "Default response"
    if custom_header:
        message += f", Custom-Header: {custom_header}"
    if track_param:
        message += f", Track: {track_param}"
    if cookie2_value:
        message += f", Cookie2: {cookie2_value}"
    
    html_response = f"""
    <html>
        <head><title>Test Endpoint</title></head>
        <body>
            <h1>Success</h1>
            <p>{message}</p>
            <h2>Received Data</h2>
            <ul>
                <li><strong>Headers:</strong>
                    <ul>
                        <li>User-Agent: {user_agent or 'None'}</li>
                        <li>Custom-Header: {custom_header or 'None'}</li>
                    </ul>
                </li>
                <li><strong>Query Parameters:</strong>
                    <ul>
                        <li>id: {id_param or 'None'}</li>
                        <li>track: {track_param or 'None'}</li>
                    </ul>
                </li>
                <li><strong>Cookies:</strong>
                    <ul>
                        <li>cookie2: {cookie2_value or 'None'}</li>
                    </ul>
                </li>
            </ul>
            <p><strong>Timestamp:</strong> {datetime.utcnow().isoformat()}Z</p>
        </body>
    </html>
    """
    return html_response, 200

@app.route('/cookie1', methods=['GET'])
def cookie1_endpoint():
    token = generate_validation_token()
    resp = make_response(f"""
    <html>
        <head><title>Cookie1 Set</title></head>
        <body>
            <h1>Success</h1>
            <p>Cookie1 has been set</p>
            <p><strong>Cookie Value:</strong> {token}</p>
        </body>
    </html>
    """)
    resp.set_cookie('cookie1', token, max_age=3600, httponly=True, secure=False, samesite='Lax')
    return resp

@app.route('/cookie2', methods=['GET'])
def cookie2_endpoint():
    token = generate_validation_token()
    resp = make_response(f"""
    <html>
        <head><title>Cookie2 Set</title></head>
        <body>
            <h1>Success</h1>
            <p>Cookie2 has been set</p>
            <p><strong>Cookie Value:</strong> {token}</p>
        </body>
    </html>
    """)
    resp.set_cookie('cookie2', token, max_age=3600, httponly=True, secure=False, samesite='Lax')
    return resp

@app.route('/cookie3', methods=['GET'])
def cookie3_endpoint():
    token = generate_validation_token()
    resp = make_response(f"""
    <html>
        <head><title>Cookie3 Set</title></head>
        <body>
            <h1>Success</h1>
            <p>Cookie3 has been set</p>
            <p><strong>Cookie Value:</strong> {token}</p>
        </body>
    </html>
    """)
    resp.set_cookie('cookie3', token, max_age=3600, httponly=True, secure=False, samesite='Lax')
    return resp

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)