def view(cursor):
    uid = int(request.args["id"])
    cursor.execute("select * from t where id = " + str(uid))


def bound(cursor):
    cursor.execute("select * from t where id = %s", (request.args["id"],))
