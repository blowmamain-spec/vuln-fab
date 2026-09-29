import tempfile

name = tempfile.mktemp()  # vuln: py-tempfile-mktemp
other = tempfile.mktemp(suffix=".txt")  # vuln: py-tempfile-mktemp
