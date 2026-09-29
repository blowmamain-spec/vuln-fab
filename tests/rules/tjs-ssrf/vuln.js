function handler(req, res, db, el) {
  const value = req.query.v;
  axios.get(value); // vuln: tjs-ssrf
}
