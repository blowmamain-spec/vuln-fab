def view(cursor):
    uid = request.args["id"]
    query = "select * from t where id = " + uid
    cursor.execute(query)  # vuln: tpy-sqli


def other(cursor):
    cursor.execute(f"select {request.form['x']}")  # vuln: tpy-sqli
