# CWE-319: Cleartext Transmission of Sensitive Information

This test suite contains positive and negative examples for CWE-319 detection in Python.

## Positives (should be detected)
- `http_request.py`: Sends sensitive data sent via HTTP (insecure).
- `ftp_connection.py`: Uses FTP, which transmit credentials in cleartext.
- `smtp_send.py`: Sends sensitive data over SMTP without TLS.
- `URL.py`: Hardcoded insecure URLS (http://, ftp://, etc).

## Negatives (should not be detected)
- `https_request.py`: Uses HTTPS (secure).
- `sftp_usage.py`: Uses SFTP (encrypted)
- `ssl_smtp.py`: Uses SMTP_SSL (encrypted email transmission).
- `URL.py`: Secure URL references (https://).
