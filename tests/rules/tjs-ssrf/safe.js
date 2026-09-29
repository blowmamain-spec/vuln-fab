function handler(req, res, db, el) {
  const value = req.query.v;
  axios.get("https://api.example.com/x", { params: { q: value } });
}
