function handler(req, res, db, el) {
  const value = req.query.v;
  fs.readFile("/data/" + value, cb); // vuln: tjs-pathtrav
}
