function handler(req, res, db, el) {
  const value = req.query.v;
  axios.get(value); // vuln: tjs-ssrf
}
async function nextRoute(request) {
  const u = request.nextUrl.searchParams.get("url");
  const r = await fetch(u); // vuln: tjs-ssrf
  return r;
}
