function handler(req, res, db, el) {
  const value = req.query.v;
  db.query("select * from t where id = $1", [value]);
  db.query("select * from t where id = " + parseInt(value));
}
