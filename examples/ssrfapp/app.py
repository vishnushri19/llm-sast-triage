from flask import Flask, request
import requests

app = Flask(__name__)

@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "http://example.com")
    response = requests.get(url, timeout=3)
    return response.text
