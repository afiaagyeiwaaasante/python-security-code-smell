import socket, ssl

# Safe: TLS-wrapped socket
context = ssl.create_default_context()
s = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname="example.com")
s.connect(("example.com", 443))
s.send(b"password=12345")
s.close()
