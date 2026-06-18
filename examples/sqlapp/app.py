import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/user")
def user_lookup():
    name = request.args.get("name", "alice")
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return str(cursor.fetchall())
