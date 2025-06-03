import json
import os
import socket
import threading
import webbrowser
from flask import Flask, jsonify, render_template_string, request
from flask_cors import CORS
from urllib.parse import urlparse
import re

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# HTML template for the web interface
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>PWManager Browser Integration</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 20px;
            background: #1f1f1f;
            color: white;
        }
        .container { 
            max-width: 600px; 
            margin: 0 auto;
            background: #2d2d2d;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
        }
        .status { 
            padding: 15px; 
            margin: 15px 0; 
            border-radius: 8px;
            text-align: center;
            font-weight: bold;
        }
        .active { 
            background-color: #4CAF50; 
            color: white;
        }
        .inactive { 
            background-color: #f44336; 
            color: white;
        }
        button { 
            padding: 12px 24px; 
            margin: 10px 5px; 
            cursor: pointer;
            border: none;
            border-radius: 6px;
            background: #2196f3;
            color: white;
            font-weight: bold;
            transition: background-color 0.3s;
        }
        button:hover {
            background: #1976d2;
        }
        h1 {
            color: #2196f3;
            text-align: center;
        }
        .password-list {
            margin-top: 20px;
            background: #363636;
            border-radius: 8px;
            padding: 15px;
        }
        .password-item {
            padding: 10px;
            margin: 5px 0;
            background: #2d2d2d;
            border-radius: 4px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .password-item .site {
            color: #2196f3;
            font-weight: bold;
        }
        .password-item .password {
            color: #4CAF50;
            font-family: 'Consolas', 'Monaco', monospace;
            background: #1f1f1f;
            padding: 5px 10px;
            border-radius: 4px;
            border: 1px solid #444;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>PWManager Browser Integration</h1>
        <div class="status active">
            Server is running on port 8080
        </div>
        <div style="text-align: center;">
            <button onclick="window.location.href='/passwords'">View Passwords</button>
            <button onclick="window.location.href='/stop'">Stop Server</button>
        </div>
        {% if passwords %}
        <div class="password-list">
            <h2>Saved Passwords:</h2>
            {% for site, password in passwords.items() %}
            <div class="password-item">
                <span class="site">{{ site }}</span>
                <span class="password">{{ password }}</span>
            </div>
            {% endfor %}
        </div>
        {% endif %}
    </div>
</body>
</html>
"""

class Extension:
    def __init__(self, password_api):
        self.password_api = password_api
        self.server = None
        self.server_thread = None
        self.description = "Browser integration for automatic password filling"
        
        # Configure Flask routes
        @app.route('/')
        def index():
            return render_template_string(HTML_TEMPLATE)
            
        @app.route('/passwords')
        def get_passwords():
            passwords = self.password_api.get_all_passwords()
            return jsonify(passwords)
            
        @app.route('/suggest/<path:url>')
        def suggest_passwords(url):
            try:
                domain = urlparse(url).netloc
                passwords = self.password_api.get_all_passwords()
                suggestions = {}
                
                for site, password in passwords.items():
                    if domain in site or site in domain:
                        suggestions[site] = password
                        
                return jsonify(suggestions)
            except Exception as e:
                return jsonify({'error': str(e)}), 400
                
        @app.route('/stop')
        def stop_server():
            def shutdown_server():
                func = request.environ.get('werkzeug.server.shutdown')
                if func is None:
                    raise RuntimeError('Not running with the Werkzeug Server')
                func()
            shutdown_server()
            return render_template_string(HTML_TEMPLATE)
            
    def start_server(self):
        if self.server is not None:
            return
            
        try:
            # Start Flask server in a separate thread
            self.server_thread = threading.Thread(
                target=lambda: app.run(host='127.0.0.1', port=8080, debug=False, use_reloader=False),
                daemon=True
            )
            self.server_thread.start()
            print("Browser integration server started on port 8080")
            
            # Open browser to show the interface
            webbrowser.open('http://127.0.0.1:8080')
            
        except Exception as e:
            print(f"Error starting server: {str(e)}")
            self.server = None
            self.server_thread = None
            
    def stop_server(self):
        if self.server_thread is not None:
            try:
                # Send shutdown request to Flask server
                import requests
                requests.get('http://127.0.0.1:8080/stop')
            except:
                pass
            finally:
                self.server = None
                self.server_thread = None
                print("Browser integration server stopped")
            
    def run(self):
        self.start_server()
        
    def cleanup(self):
        self.stop_server() 