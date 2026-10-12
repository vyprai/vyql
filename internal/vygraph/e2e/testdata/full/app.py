import flask
from db import session

@flask.route("/users")
def list_users(req):
    q = req.args.get("q")
    sql = "SELECT * FROM users WHERE name = " + q
    rows = session.execute(sql)
    return rows

def encrypt_secret(key):
    c = cipher.new(key, cipher.MODE_ECB)
    return c
