function handler(req, db) {
  db.query("select * from t where id = $1", [req.params.id]);
  const n = parseInt(req.query.n);
  db.query("select * from t limit " + n);
}
