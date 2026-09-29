import yaml

a = yaml.safe_load(data)
b = yaml.load(data, Loader=yaml.SafeLoader)
c = yaml.dump(data)
