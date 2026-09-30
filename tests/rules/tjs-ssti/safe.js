function view(req, res, ejs) {
  res.render("profile", { name: req.query.name });
  const out = ejs.render("<p><%= name %></p>", { name: req.body.name });
  res.send(out);
}
