function handler(req, res, db, el) {
  const value = req.query.v;
  eval(value); // vuln: tjs-codei
}
