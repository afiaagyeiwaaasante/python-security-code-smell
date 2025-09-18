# CWE-319: Cleartext Transmission of Sensitive Information

This test suite contains positive and negative examples for CWE-319 detection in Python.

## Positives (should be detected)
- `http_request.py`: Sensitive data sent via HTTP (requests).
- `raw_socket.py`: Unencrypted socket on port 80.
- `ftp_usage.py`: FTP transmits credentials in cleartext.
- `telnet_usage.py`: Telnet transmits data in cleartext.

## Negatives (should not be detected)
- `https_request.py`: Encrypted HTTPS request.
- `tls_socket.py`: TLS-wrapped socket connection.
- `sftp_usage.py`: SFTP connection with encryption.
