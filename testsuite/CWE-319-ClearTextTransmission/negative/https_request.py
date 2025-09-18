import requests

# Safe: uses HTTPS
requests.post("https://example.com/login", data={"password": "12345"})
