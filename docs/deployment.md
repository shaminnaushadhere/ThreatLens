# ThreatLens Deployment Guide (Render)

## Prerequisites

Before deployment, make sure:

* The project is uploaded to GitHub.
* A valid AbuseIPDB API key is available.
* The `.env` file is NOT uploaded to GitHub.

---

## Required Files

The repository should contain:

* app.py
* analyzer.py
* requirements.txt
* templates/
* static/
* docs/
* screenshots/

---

## Add Gunicorn

Add the following line to `requirements.txt`:

gunicorn

Example:

flask
PyPDF2
reportlab
python-dotenv
requests
gunicorn

---

## Push to GitHub

Initialize Git:

git init

Add files:

git add .

Create commit:

git commit -m "Initial ThreatLens deployment"

Push to GitHub.

---

## Create Render Account

1. Go to https://render.com
2. Sign in with GitHub.
3. Click "New +"
4. Select "Web Service"

---

## Connect Repository

Select the ThreatLens GitHub repository.

---

## Deployment Settings

Build Command:

pip install -r requirements.txt

Start Command:

gunicorn app:app

---

## Environment Variables

In Render Dashboard:

Settings → Environment Variables

Add:

ABUSEIPDB_API_KEY = your_api_key_here

Do not upload the .env file.

---

## Deploy

Click:

Create Web Service

Render will:

* Install dependencies
* Build the application
* Start the Flask server

---

## Public URL

After deployment, Render generates a public URL:

https://threatlens.onrender.com

Anyone can open the link and use the application through a browser.

---

## Post-Deployment Testing

Verify:

* Demo buttons work
* PDF upload works
* IOC extraction works
* AbuseIPDB lookup works
* PDF report generation works
* CSV export works

---

## Notes

The free Render tier may place the application into sleep mode after inactivity. The first request after inactivity may take several seconds to load.
