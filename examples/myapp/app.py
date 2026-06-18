import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    cmd = "ping -c 1 " + host
    return subprocess.check_output(cmd, shell=True).decode()