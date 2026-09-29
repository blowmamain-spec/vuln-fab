function handler(req, res, db, el) {
  const value = req.query.v;
  res.redirect("/home");
}
