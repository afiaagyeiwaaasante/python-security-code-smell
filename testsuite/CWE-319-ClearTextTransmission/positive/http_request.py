import requests

# CWE-319: sending sensitive info over HTTP (cleartext)
requests.post("http://example.com/login", data={"password": "12345"})
