import flask

@flask.route("/users")
def list_users(req):
    q = req.args.get("q")
    rows = session.execute("SELECT * FROM users WHERE n = " + q)
    return rows
