import socket

# CWE-319: socket connection without TLS
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("example.com", 80))
s.send(b"password=12345")
s.close()
