import paramiko

# Safe: SFTP is encrypted
transport = paramiko.Transport(("example.com", 22))
transport.connect(username="admin", password="12345")
sftp = paramiko.SFTPClient.from_transport(transport)
