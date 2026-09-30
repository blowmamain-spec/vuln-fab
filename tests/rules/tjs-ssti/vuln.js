function view(req, res, ejs) {
  res.render(req.query.tpl, { a: 1 }); // vuln: tjs-ssti
  const out = ejs.render(req.body.template, {}); // vuln: tjs-ssti
  res.send(out);
}
