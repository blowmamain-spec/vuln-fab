function handler(req, res, db, el) {
  const value = req.query.v;
  Model.findByPk(value); // vuln: tjs-idor
}
