function update(req, res, _, cfg) {
  _.merge(cfg, { theme: "dark" });
  _.set(cfg, "a.b", req.body.value);
  res.end();
}
