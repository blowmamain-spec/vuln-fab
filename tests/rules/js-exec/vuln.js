const child_process = require("child_process");
child_process.exec("convert " + file, cb); // vuln: js-exec
child_process.execSync(`ls ${dir}`); // vuln: js-exec
exec(cmd, (err) => {}); // vuln: js-exec
