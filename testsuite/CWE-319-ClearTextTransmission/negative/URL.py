import http.client
conn = http.client.HTTPSConnection("example.com") # should NOT be flagged
