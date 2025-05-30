#!/usr/bin/env python3
"""
Route module for the API
"""
from os import getenv
from api.v1.views import app_views
from flask import Flask, jsonify, abort, request
from flask_cors import CORS, cross_origin
import os

# Import SessionAuth if needed
auth = None

if getenv('AUTH_TYPE') == 'auth':
    from api.v1.auth.auth import Auth
    auth = Auth()

elif getenv('AUTH_TYPE') == 'basic_auth':
    from api.v1.auth.basic_auth import BasicAuth
    auth = BasicAuth()

elif getenv('AUTH_TYPE') == 'session_auth':
    from api.v1.auth.session_auth import SessionAuth
    auth = SessionAuth()

# If AUTH_TYPE is not defined or has an unknown value, abort.

app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})


@app.errorhandler(404)
def not_found(error) -> str:
    """ Not found handler """
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(401)
def access_denied(error) -> str:
    """ Unauthorized handler """
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def access_forbidden(error) -> str:
    """ Forbidden handler """
    return jsonify({"error": "Forbidden"}), 403


@app.before_request
def before_request_handler():
    """before_request handler"""
    excluded = ['/api/v1/status/',
                '/api/v1/unauthorized/',
                '/api/v1/forbidden/',
                '/api/v1/auth_session/login/']

    if auth is not None and auth.require_auth(request.path, excluded):
        if (auth.authorization_header(request) is None
                and auth.session_cookie(request) is None):
            abort(401)

        user = auth.current_user(request)
        if user is None:
            abort(403)
        request.current_user = user  # Assign current_user to request


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
