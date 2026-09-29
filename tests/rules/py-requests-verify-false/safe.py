import requests

requests.get(url)
requests.get(url, verify=True)
requests.get(url, verify="/etc/ssl/ca.pem")
session.get(url, verify=False)
