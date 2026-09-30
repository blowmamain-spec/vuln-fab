function handler(req, res, db, el) {
  const value = req.query.v;
  res.redirect(value); // vuln: tjs-redirect
}
function client() {
  const next = new URLSearchParams(window.location.search);
  window.location.href = window.location.hash; // vuln: tjs-redirect
  location.assign(document.referrer); // vuln: tjs-redirect
}
async function nextRoute(request) {
  const to = request.nextUrl.searchParams.get("to");
  return NextResponse.redirect(to); // vuln: tjs-redirect
}
export default function Page({ searchParams }) {
  redirect(searchParams.next); // vuln: tjs-redirect
}
