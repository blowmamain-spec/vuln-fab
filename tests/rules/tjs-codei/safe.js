function handler(req, res, db, el) {
  const value = req.query.v;
  eval("1 + " + Number(value));
}
