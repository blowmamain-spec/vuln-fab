function handler(req, db) {
  const id = req.params.id;
  db.query("select * from t where id = " + id); // vuln: tjs-sqli
}
