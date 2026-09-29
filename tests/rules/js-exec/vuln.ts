import { exec } from "node:child_process";
exec("convert " + file + " out.png", () => res.end("ok")); // vuln: js-exec
