import pickle
import cPickle

a = pickle.loads(blob)  # vuln: py-pickle-loads
b = pickle.load(open("f", "rb"))  # vuln: py-pickle-loads
c = cPickle.loads(blob)  # vuln: py-pickle-loads
