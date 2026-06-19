from flask import Flask, request
import yaml

app = Flask(__name__)

@app.route("/load", methods=["POST"])
def load_yaml():
    document = request.data.decode("utf-8")
    parsed = yaml.load(document, Loader=yaml.Loader)
    return str(parsed)
