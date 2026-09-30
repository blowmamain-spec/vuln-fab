async function like(req, res, db, Address) {
  const id = Number(req.body.id);
  const review = await db.reviewsCollection.findOne({ _id: id });
  const a = await Address.findOne({ where: { id: req.params.id } });
  res.json([review, a]);
}
