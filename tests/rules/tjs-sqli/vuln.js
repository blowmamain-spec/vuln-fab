function handler(req, res, db, el) {
  const value = req.query.v;
  db.query("select * from t where id = " + value); // vuln: tjs-sqli
}
