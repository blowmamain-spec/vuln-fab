import yaml

a = yaml.load(data)  # vuln: py-yaml-load
b = yaml.load(data, Loader=yaml.Loader)  # vuln: py-yaml-load
c = yaml.load(data, Loader=yaml.UnsafeLoader)  # vuln: py-yaml-load
d = yaml.load(data, yaml.Loader)  # vuln: py-yaml-load
