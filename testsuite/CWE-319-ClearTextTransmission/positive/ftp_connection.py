from ftplib import FTP

# CWE-319: using FTP without encryption (cleartext)
ftp = FTP("ftp.example.com")  # should be flagged

