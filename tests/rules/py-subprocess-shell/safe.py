import subprocess

subprocess.run(["ls", path])
subprocess.run(cmd, shell=False)
subprocess.run("ls -l", shell=True)
subprocess.run(cmd)
other.run(cmd, shell=True)
