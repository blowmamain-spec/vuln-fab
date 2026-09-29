function handler(req, res, db, el) {
  const value = req.query.v;
  serialize.unserialize(value); // vuln: tjs-deser
}
