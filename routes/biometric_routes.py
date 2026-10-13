"""
BioCrypt — Biometric (WebAuthn) API Routes
"""
from flask import Blueprint, jsonify, request, session
from auth.biometric_auth import (
    begin_registration,
    complete_registration,
    begin_authentication,
    complete_authentication,
    is_available,
    unavailable_reason,
)

biometric_bp = Blueprint('biometric', __name__)

@biometric_bp.route('/api/biometric/register/begin', methods=['POST'])
def api_register_begin():
    data = request.get_json(silent=True) or {}
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    username = data.get('username') or session.get('username')
    options = begin_registration(user_id, username)
    return jsonify(options)

@biometric_bp.route('/api/biometric/register/complete', methods=['POST'])
def api_register_complete():
    data = request.get_json(silent=True) or {}
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    try:
        success = complete_registration(user_id, data)
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@biometric_bp.route('/api/biometric/authenticate/begin', methods=['POST'])
def api_authenticate_begin():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    options = begin_authentication(user_id)
    return jsonify(options)

@biometric_bp.route('/api/biometric/authenticate/complete', methods=['POST'])
def api_authenticate_complete():
    data = request.get_json(silent=True) or {}
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    try:
        success = complete_authentication(user_id, data)
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@biometric_bp.route('/api/biometric/status', methods=['GET'])
def api_biometric_status():
    available = is_available()
    return jsonify({'available': available, 'reason': None if available else unavailable_reason()})
