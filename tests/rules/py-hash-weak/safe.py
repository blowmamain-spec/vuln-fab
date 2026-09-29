import hashlib

a = hashlib.sha256(data)
b = hashlib.md5(data, usedforsecurity=False)
c = hashlib.sha1(data, usedforsecurity=False)
