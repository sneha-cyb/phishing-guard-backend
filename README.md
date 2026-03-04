PhishGuard Backend
PhishGuard Backend is a lightweight REST API built using Node.js and Express.js that analyzes URLs to detect potential phishing threats.

The backend receives a URL from the client, checks it using the Google Safe Browsing API, and returns a security response indicating whether the link is safe or potentially malicious.

This service is designed to be integrated with applications that require real-time phishing link detection.

My Role

Backend Developer

Responsibilities:

Designed and implemented the backend server

Developed the phishing detection API

Integrated Google Safe Browsing API for threat analysis

Implemented URL scanning and response handling

Performed backend setup and testing

ech Stack

Node.js

Express.js

Google Safe Browsing API

Running the Backend

Navigate to the project directory.

cd phishing-guard-backend

Install dependencies.

npm install

Start the backend server.

npm run dev

The API will start running on:

http://localhost:3000
Checking Server Health

Open another terminal and run:

curl http://localhost:3000/health

Expected response:

status: ok

This confirms that the PhishGuard API is running successfully.

Scanning a URL

You can test the phishing detection API using a POST request.

Example:

curl -X POST http://localhost:3000/api/scan \
-H "Content-Type: application/json" \
-d '{"url":"https://example.com"}'

The backend will analyze the URL using Google Safe Browsing and return the security result.
