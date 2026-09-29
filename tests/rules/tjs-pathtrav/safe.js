function handler(req, res, db, el) {
  const value = req.query.v;
  fs.readFile("/data/" + path.basename(value), cb);
}
