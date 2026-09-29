export function calc(req: { body: { json: string } }) {
  const a = eval("1 + 1");
  const b = JSON.parse(req.body.json);
  const f = new Function("return 1");
  return [a, b, f];
}
