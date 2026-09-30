function handler(req, res, db, el) {
  const value = req.query.v;
  res.send("<p>" + value + "</p>"); // vuln: tjs-xss
  el.innerHTML = value; // vuln: tjs-xss
}
function domXss() {
  const h = window.location.hash;
  document.getElementById("out").innerHTML = h; // vuln: tjs-xss
  const q = new URLSearchParams(window.location.search);
  const name = localStorage.getItem("name");
  $("#box").html(name); // vuln: tjs-xss
}
async function nextRoute(request) {
  const body = await request.json();
  return new Response("<p>" + body.msg + "</p>");
}
