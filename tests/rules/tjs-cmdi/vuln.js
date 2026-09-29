function handler(req, res, db, el) {
  const value = req.query.v;
  child_process.exec("ping " + value); // vuln: tjs-cmdi
}
