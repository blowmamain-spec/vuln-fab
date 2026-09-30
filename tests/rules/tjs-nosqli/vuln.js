async function like(req, res, db) {
  const id = req.body.id;
  const review = await db.reviewsCollection.findOne({ _id: id }); // vuln: tjs-nosqli
  const rows = await db.reviewsCollection.find({ $where: "this.p == " + req.params.id }); // vuln: tjs-nosqli
  res.json([review, rows]);
}
