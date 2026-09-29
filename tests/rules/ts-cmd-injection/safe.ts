import { exec, execFile } from "node:child_process";

export function run(file: string) {
  execFile("convert", [file, "out.png"], () => {});
  exec("uname -a", () => {});
  const m = /a(b)/.exec(file);
}
