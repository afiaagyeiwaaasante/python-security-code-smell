import smtplib

# CWE-319: sending sensitive info over SMTP without encryption (cleartext)
server = smtplib.SMTP("mail.example.com", 25) 
server.login("user", "password123")   # should be flagged
