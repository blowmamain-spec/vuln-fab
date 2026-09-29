import os

os.system(cmd)  # vuln: py-os-system
os.system("ls " + name)  # vuln: py-os-system
