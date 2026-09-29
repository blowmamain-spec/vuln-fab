function handler(req, res, db, el) {
  const value = req.query.v;
  res.send("<p>" + escapeHtml(value) + "</p>");
  el.innerHTML = DOMPurify.sanitize(value);
}
