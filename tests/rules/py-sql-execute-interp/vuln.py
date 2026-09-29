def f(cursor, uid, name):
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # vuln: py-sql-execute-interp
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")  # vuln: py-sql-execute-interp
    cursor.execute("SELECT * FROM t WHERE id = %s" % uid)  # vuln: py-sql-execute-interp
    cursor.execute("SELECT * FROM t WHERE id = {}".format(uid))  # vuln: py-sql-execute-interp
    self.conn.cursor().execute(f"DELETE FROM t WHERE id = {uid}", ())  # vuln: py-sql-execute-interp
