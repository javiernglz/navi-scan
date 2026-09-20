# navi-scan

Reads nmap output and prints ready-to-run enumeration commands for every open port.

## Usage

```bash
python3 navi-scan.py TARGET scan.xml
python3 navi-scan.py TARGET scan.txt
python3 navi-scan.py TARGET scan.xml -o report.md
```

## Supported services

| Port | Service |
|------|---------|
| 21   | FTP     |
| 22   | SSH     |
| 25   | SMTP    |
| 80   | HTTP    |
| 443  | HTTPS   |
| 389  | LDAP    |
| 445  | SMB     |
| 636  | LDAPS   |
| 1433 | MSSQL   |
| 3306 | MySQL   |
| 3389 | RDP     |
| 5985 | WinRM   |

## Requirements

Python 3.6+. No external dependencies.

## License

MIT
