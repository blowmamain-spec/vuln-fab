import { exec, execSync } from "node:child_process";

export function run(req: { query: { file: string } }) {
  exec("convert " + req.query.file + " out.png", () => {}); // vuln: ts-cmd-injection
  execSync(`ls ${req.query.file}`); // vuln: ts-cmd-injection
}
