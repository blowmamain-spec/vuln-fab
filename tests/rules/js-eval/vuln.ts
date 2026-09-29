const r = eval(input as string); // vuln: js-eval
export const g = (s: string): unknown => eval(s); // vuln: js-eval
