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

## Example

```
  navi-scan  ·  10.10.10.1
  scan.xml  ·  3 open port(s) found

  Port 22  SSH
  Grab the banner for version info. Brute-force only if no other path.

    ssh -v 10.10.10.1
    nmap -p 22 --script ssh-auth-methods,ssh2-enum-algos 10.10.10.1
    hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.1

  Port 445  SMB
  High priority. List shares, enumerate users, check for known exploits.

    smbclient -L //10.10.10.1 -N
    enum4linux -a 10.10.10.1
    crackmapexec smb 10.10.10.1
    nmap -p 445 --script smb-vuln* 10.10.10.1
    smbmap -H 10.10.10.1

  Port 3389  RDP
  Check for BlueKeep / DejaBlue. Try creds if you have any.

    nmap -p 3389 --script rdp-enum-encryption,rdp-vuln-ms12-020 10.10.10.1
    xfreerdp /v:10.10.10.1 /u:administrator /p:''
    ncrack -p 3389 --user administrator -P /usr/share/wordlists/rockyou.txt 10.10.10.1
```

## Requirements

Python 3.6+. No external dependencies.

## License

MIT
