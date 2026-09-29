export function calc(req: { body: { expr: string } }) {
  const a = eval(req.body.expr); // vuln: ts-dynamic-eval
  const f = new Function("x", req.body.expr); // vuln: ts-dynamic-eval
  return [a, f];
}
