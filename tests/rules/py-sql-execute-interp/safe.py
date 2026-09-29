def f(cursor, uid, query):
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
    cursor.execute("SELECT 1")
    cursor.execute("SELECT * " + "FROM users")
    cursor.execute(query)
    cursor.execute(f"no interpolation here")
    executor.run(f"SELECT {uid}")
