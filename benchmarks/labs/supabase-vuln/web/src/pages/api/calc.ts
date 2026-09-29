import type { NextApiRequest, NextApiResponse } from "next";

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  // @lab vuln dynamic-eval cwe=CWE-95 tier=A :: eval atas input request
  const result = eval(req.body.expr);
  // @lab decoy dynamic-eval cwe=CWE-95 :: parsing JSON
  const parsed = JSON.parse(req.body.json);
  res.json({ result, parsed });
}
