const f = new Function(code); // vuln: js-function-constructor
const g = new Function("a", "b", body); // vuln: js-function-constructor
