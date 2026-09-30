async function sequelizeStyle(req, res, Address) {
  // a SQL ORM: scalar values in `where` are bound as parameters
  const a = await Address.findOne({ where: { id: req.params.id } });
  res.json(a);
}
