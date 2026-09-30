const mongoose = require("mongoose"); // model layer
async function login(req, res, User) {
  const u = await User.findOne({ name: req.body.name, pass: req.body.pass }); // vuln: tjs-nosqli-odm
  const all = await User.find(req.body); // vuln: tjs-nosqli-odm
  res.json([u, all]);
}
