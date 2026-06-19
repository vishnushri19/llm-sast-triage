from flask import Flask, request, redirect

app = Flask(__name__)

@app.route("/go")
def go():
    next_url = request.args.get("next", "/")
    return redirect(next_url)
