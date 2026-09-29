import { exec, execFile } from "node:child_process";
import type { NextApiRequest, NextApiResponse } from "next";

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  const file = String(req.query.file);
  // @lab vuln cmd-injection cwe=CWE-78 tier=A :: input request masuk ke exec
  exec("convert " + file + " out.png", () => res.end("ok"));
  // @lab decoy cmd-injection cwe=CWE-78 :: execFile dengan argumen konstan
  execFile("convert", ["input.png", "out.png"], () => res.end("ok"));
  // @lab decoy cmd-injection cwe=CWE-78 :: perintah literal
  exec("uname -a", () => res.end("ok"));
}
