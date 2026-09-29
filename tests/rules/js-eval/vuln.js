eval(userInput); // vuln: js-eval
const r = eval("a" + b); // vuln: js-eval
function f(req) {
  return eval(req.body.expr); // vuln: js-eval
}
