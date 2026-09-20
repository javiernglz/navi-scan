# navi-scan

A Python script that reads nmap output (XML or plain text) and prints ready-to-run enumeration commands for every open port it recognises.

Inspired by [rasbora](https://github.com/XoanOuteiro/rasbora) — the idea is the same: skip the googling, get straight to the commands.

## Usage

```bash
# from nmap XML output
python3 navi-scan.py 10.10.10.1 scan.xml

# from normal nmap text output
python3 navi-scan.py 10.10.10.1 scan.txt

# save to markdown (useful for OSCP notes)
python3 navi-scan.py 10.10.10.1 scan.xml -o report.md
```

## Supported services

| Port | Service |
|------|---------|
| 21   | FTP |
| 22   | SSH |
| 25   | SMTP |
| 80   | HTTP |
| 443  | HTTPS |
| 389  | LDAP |
| 445  | SMB |
| 636  | LDAPS |
| 1433 | MSSQL |
| 3306 | MySQL |
| 3389 | RDP |
| 5985 | WinRM |

## Example output

```
  navi-scan  ·  10.10.10.1
  scan.xml  ·  3 open port(s) found

  Port 22  SSH
  Grab the banner for version info. Brute-force only if no other path.

    ssh -v 10.10.10.1
    nmap -p 22 --script ssh-auth-methods,ssh2-enum-algos 10.10.10.1
    hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.1

  Port 80  HTTP
  Enumerate directories, fingerprint the stack, look for known vulns.

    gobuster dir -u http://10.10.10.1 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
    nikto -h http://10.10.10.1
    whatweb http://10.10.10.1
    curl -v http://10.10.10.1

  Port 445  SMB
  High priority. List shares, enumerate users, check for known exploits.

    smbclient -L //10.10.10.1 -N
    enum4linux -a 10.10.10.1
    crackmapexec smb 10.10.10.1
    nmap -p 445 --script smb-vuln* 10.10.10.1
    smbmap -H 10.10.10.1
```

## Requirements

No external dependencies. Python 3.6+.

## License

MIT
