import os
import shlex


def handler(cursor):
    value = request.args["v"]
    cursor.execute("select * from t where id = %s", (value,))
    cursor.execute("select * from t where id = " + str(int(value)))
