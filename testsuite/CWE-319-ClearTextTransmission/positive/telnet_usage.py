from ftplib import FTP

# CWE-319: FTP transmits credentials in cleartext
ftp = FTP("ftp.example.com")
ftp.login(user="admin", passwd="12345")
