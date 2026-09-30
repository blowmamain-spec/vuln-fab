function update(req, res, _, cfg) {
  _.merge(cfg, req.body); // vuln: tjs-protopollution
  _.set(cfg, req.body.path, 1); // vuln: tjs-protopollution
  res.end();
}
