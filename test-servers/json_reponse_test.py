from flask import Flask, request, jsonify, make_response
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
        return jsonify({'error': 'User-Agent header is required'}), 400
    
    # Essential query param check: id
    if not id_param:
        return jsonify({'error': 'id query parameter is required'}), 400
    
    # Get cookie2 value (if present)
    cookie2_value = request.cookies.get('cookie2')
    
    # Response
    response = {
        'status': 'success',
        'received': {
            'headers': {
                'User-Agent': user_agent,
                'Custom-Header': custom_header
            },
            'query_params': {
                'id': id_param,
                'track': track_param
            },
            'cookies': {
                'cookie2': cookie2_value
            }
        },
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        "generate_validation_token": generate_validation_token()
    }
    
    response['message'] = 'Default response'
    if custom_header:
        response['message'] += f', Custom-Header: {custom_header}'
    if track_param:
        response['message'] += f', Track: {track_param}'
    if cookie2_value:
        response['message'] += f', Cookie2: {cookie2_value}'
    
    return jsonify(response), 200


@app.route('/cookie1', methods=['GET'])
def cookie1_endpoint():
    token = generate_validation_token()
    resp = make_response(jsonify({
        'status': 'success',
        'message': 'Cookie1 has been set',
        'cookie_value': token
    }))
    resp.set_cookie('cookie1', token, max_age=3600, httponly=True, secure=False, samesite='Lax')
    return resp


@app.route('/cookie2', methods=['GET'])
def cookie2_endpoint():
    token = generate_validation_token()
    resp = make_response(jsonify({
        'status': 'success',
        'message': 'Cookie2 has been set',
        'cookie_value': token
    }))
    resp.set_cookie('cookie2', token, max_age=3600, httponly=True, secure=False, samesite='Lax')
    return resp


@app.route('/cookie3', methods=['GET'])
def cookie3_endpoint():
    token = generate_validation_token()
    resp = make_response(jsonify({
        'status': 'success',
        'message': 'Cookie3 has been set',
        'cookie_value': token
    }))
    resp.set_cookie('cookie3', token, max_age=3600, httponly=True, secure=False, samesite='Lax')
    return resp


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)