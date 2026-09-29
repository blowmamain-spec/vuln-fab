import subprocess

subprocess.run(cmd, shell=True)  # vuln: py-subprocess-shell
subprocess.call("ls " + path, shell=True)  # vuln: py-subprocess-shell
subprocess.Popen(cmd, stdout=PIPE, shell=True)  # vuln: py-subprocess-shell
subprocess.check_output(f"cat {name}", shell=True)  # vuln: py-subprocess-shell
