function handler(req, res, db, el) {
  const value = req.query.v;
  const owner = req.user.id;
  Model.findByPk(value);
}
