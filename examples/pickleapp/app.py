from flask import Flask, request
import base64
import pickle

app = Flask(__name__)

@app.route("/restore")
def restore_object():
    payload = request.args.get("payload", "")
    obj = pickle.loads(base64.b64decode(payload))
    return str(obj)
