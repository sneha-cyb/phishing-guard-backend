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

Navigate to the backend directory.

cd phishing-guard-backend

Install dependencies.

npm install

Start the server.

node server.js

The phishing detection API will start running on:

http://localhost:3000
Testing the Server

Open another browser tab and check the server.

Example:

http://localhost:3000

Provide a malicious or suspicious URL to the API endpoint, and the backend will analyze the link using Google Safe Browsing and return the security result.
