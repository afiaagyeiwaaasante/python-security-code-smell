import smtplib
server = smtplib.SMTP_SSL("mail.example.com", 465)
server.login("user", "password123")   # should NOT be flagged
