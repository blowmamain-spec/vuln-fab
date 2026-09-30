const mongoose = require("mongoose");
async function login(req, res, User) {
  const u = await User.findOne({ name: String(req.body.name) });
  const v = await User.findOne({ _id: parseInt(req.params.id) });
  const list = [1, 2, 3].find((n) => n === 2);
  res.json([u, v, list]);
}
