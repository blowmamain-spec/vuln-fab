function handler(req, res, db, el) {
  const value = req.query.v;
  res.send("<p>" + value + "</p>"); // vuln: tjs-xss
  el.innerHTML = value; // vuln: tjs-xss
}
