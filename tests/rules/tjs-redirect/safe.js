function handler(req, res, db, el) {
  const value = req.query.v;
  res.redirect("/home");
}
function client() {
  window.location.href = "/home";
  location.assign("/login");
}
async function nextRoute(request) {
  const to = request.nextUrl.searchParams.get("to");
  if (!isRedirectAllowed(to)) return NextResponse.redirect("/");
  return NextResponse.redirect(to);
}
