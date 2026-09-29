import tempfile

fd, path = tempfile.mkstemp()
f = tempfile.NamedTemporaryFile()
d = tempfile.mkdtemp()
