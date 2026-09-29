import hashlib

a = hashlib.md5(pw.encode()).hexdigest()  # vuln: py-hash-weak
b = hashlib.sha1(data)  # vuln: py-hash-weak
