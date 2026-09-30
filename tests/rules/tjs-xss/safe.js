function handler(req, res, db, el) {
  const value = req.query.v;
  res.send("<p>" + escapeHtml(value) + "</p>");
  el.innerHTML = DOMPurify.sanitize(value);
}
function domSafe() {
  const h = window.location.hash;
  document.getElementById("out").innerHTML = DOMPurify.sanitize(h);
  const name = localStorage.getItem("name");
  $("#box").text(name);
}
