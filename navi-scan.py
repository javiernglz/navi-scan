#!/usr/bin/env python3
"""
navi-scan — reads nmap output (XML or normal text) and prints
enumeration commands for every open port it recognises.

Usage:
    navi-scan TARGET scan.xml
    navi-scan TARGET scan.txt
    navi-scan TARGET scan.xml -o report.md
"""

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# ── colours ──────────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[1;36m"
GREEN  = "\033[1;32m"
YELLOW = "\033[1;33m"
RED    = "\033[1;31m"
GREY   = "\033[90m"

def c(colour, text):
    return f"{colour}{text}{RESET}"

# ── service definitions ───────────────────────────────────────────────────────
# Each entry: (label, colour, reason, [commands_template])
# {T} = target IP/host
SERVICES = {
    21: (
        "FTP",
        GREEN,
        "Check for anonymous login and grab any exposed files.",
        [
            "ftp {T}",
            "nmap -p 21 --script ftp-anon,ftp-syst,ftp-bounce {T}",
            "wget -r --no-passive ftp://anonymous:anonymous@{T}/",
        ],
    ),
    22: (
        "SSH",
        GREEN,
        "Grab the banner for version info. Brute-force only if no other path.",
        [
            "ssh -v {T}",
            "nmap -p 22 --script ssh-auth-methods,ssh2-enum-algos {T}",
            "hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{T}",
        ],
    ),
    25: (
        "SMTP",
        YELLOW,
        "Enumerate valid users with VRFY/RCPT TO.",
        [
            "nmap -p 25 --script smtp-enum-users,smtp-commands {T}",
            "smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {T}",
            'nc {T} 25\n    EHLO test\n    VRFY root',
        ],
    ),
    80: (
        "HTTP",
        CYAN,
        "Enumerate directories, fingerprint the stack, look for known vulns.",
        [
            "gobuster dir -u http://{T} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt",
            "nikto -h http://{T}",
            "whatweb http://{T}",
            "curl -v http://{T}",
        ],
    ),
    443: (
        "HTTPS",
        CYAN,
        "Same as HTTP — also check the certificate for hostnames.",
        [
            "gobuster dir -u https://{T} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -k",
            "nikto -h https://{T} -ssl",
            "whatweb https://{T}",
            "curl -vk https://{T}",
            "echo | openssl s_client -connect {T}:443 2>/dev/null | openssl x509 -noout -text | grep -E 'Subject|DNS'",
        ],
    ),
    389: (
        "LDAP",
        YELLOW,
        "Try anonymous bind first. If it works, dump everything.",
        [
            "ldapsearch -x -H ldap://{T} -b '' -s base namingContexts",
            "ldapsearch -x -H ldap://{T} -b 'DC=domain,DC=local'",
            "nmap -p 389 --script ldap-search,ldap-rootdse {T}",
        ],
    ),
    445: (
        "SMB",
        RED,
        "High priority. List shares, enumerate users, check for known exploits.",
        [
            "smbclient -L //{T} -N",
            "enum4linux -a {T}",
            "crackmapexec smb {T}",
            "nmap -p 445 --script smb-vuln* {T}",
            "smbmap -H {T}",
        ],
    ),
    636: (
        "LDAPS",
        YELLOW,
        "LDAP over TLS — same enumeration as LDAP but encrypted.",
        [
            "ldapsearch -x -H ldaps://{T} -b '' -s base namingContexts",
            "nmap -p 636 --script ldap-search {T}",
        ],
    ),
    1433: (
        "MSSQL",
        RED,
        "Try default creds. If you get in, xp_cmdshell might be enabled.",
        [
            "nmap -p 1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-config {T}",
            "impacket-mssqlclient sa:@{T} -windows-auth",
            "crackmapexec mssql {T} -u sa -p ''",
        ],
    ),
    3306: (
        "MySQL",
        YELLOW,
        "Check for anonymous or default creds, look for interesting databases.",
        [
            "mysql -h {T} -u root -p",
            "nmap -p 3306 --script mysql-info,mysql-empty-password,mysql-databases {T}",
            "mysqldump -h {T} -u root --all-databases",
        ],
    ),
    3389: (
        "RDP",
        RED,
        "Check for BlueKeep / DejaBlue. Try creds if you have any.",
        [
            "nmap -p 3389 --script rdp-enum-encryption,rdp-vuln-ms12-020 {T}",
            "xfreerdp /v:{T} /u:administrator /p:''",
            "ncrack -p 3389 --user administrator -P /usr/share/wordlists/rockyou.txt {T}",
        ],
    ),
    5985: (
        "WinRM",
        RED,
        "If you have creds or a hash, this is your shell.",
        [
            "evil-winrm -i {T} -u administrator -p 'password'",
            "evil-winrm -i {T} -u administrator -H <NTHASH>",
            "crackmapexec winrm {T} -u administrator -p 'password'",
        ],
    ),
}

# ── parsers ───────────────────────────────────────────────────────────────────

def parse_xml(path: Path) -> list[int]:
    """Return list of open TCP ports from an nmap XML file."""
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        sys.exit(f"[!] XML parse error: {e}")

    ports = []
    for port in tree.findall(".//port"):
        state = port.find("state")
        if state is not None and state.get("state") == "open":
            ports.append(int(port.get("portid")))
    return ports


def parse_text(path: Path) -> list[int]:
    """Return list of open TCP ports from a normal nmap text output."""
    ports = []
    pattern = re.compile(r"^(\d+)/tcp\s+open", re.MULTILINE)
    text = path.read_text(errors="replace")
    for m in pattern.finditer(text):
        ports.append(int(m.group(1)))
    return ports


def detect_and_parse(path: Path) -> list[int]:
    content = path.read_bytes()
    if content.lstrip().startswith(b"<?xml") or content.lstrip().startswith(b"<"):
        return parse_xml(path)
    return parse_text(path)

# ── renderer ──────────────────────────────────────────────────────────────────

def render_service(port: int, target: str, md: bool) -> list[str]:
    name, colour, reason, cmds = SERVICES[port]
    lines = []

    if md:
        lines.append(f"\n## Port {port} — {name}\n")
        lines.append(f"> {reason}\n")
        lines.append("```bash")
        for cmd in cmds:
            lines.append(cmd.replace("{T}", target))
        lines.append("```")
    else:
        lines.append("")
        lines.append(c(colour, f"  Port {port}  {name}"))
        lines.append(c(GREY, f"  {reason}"))
        lines.append("")
        for cmd in cmds:
            lines.append("    " + cmd.replace("{T}", target))

    return lines


def render_unknown(unknown: list[int], md: bool) -> list[str]:
    if not unknown:
        return []
    ports_str = ", ".join(str(p) for p in sorted(unknown))
    if md:
        return [f"\n## Unrecognised ports\n\n{ports_str}\n"]
    return [
        "",
        c(GREY, f"  Unrecognised open ports: {ports_str}"),
        c(GREY, "  Run nmap scripts manually or check with netcat."),
    ]

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="navi-scan: map nmap ports to enumeration commands"
    )
    parser.add_argument("target", help="target IP or hostname")
    parser.add_argument("scan", help="nmap output file (.xml or .txt)")
    parser.add_argument("-o", "--output", help="save output to this file")
    args = parser.parse_args()

    scan_path = Path(args.scan)
    if not scan_path.is_file():
        sys.exit(f"[!] File not found: {scan_path}")

    ports = detect_and_parse(scan_path)
    if not ports:
        sys.exit("[!] No open ports found in the file.")

    md = False
    if args.output and args.output.endswith(".md"):
        md = True

    known   = sorted(p for p in ports if p in SERVICES)
    unknown = sorted(p for p in ports if p not in SERVICES)

    all_lines = []

    if md:
        all_lines.append(f"# navi-scan — {args.target}\n")
        all_lines.append(f"Source: `{scan_path.name}`\n")
    else:
        print()
        print(c(BOLD, f"  navi-scan  ·  {args.target}"))
        print(c(GREY,  f"  {scan_path.name}  ·  {len(ports)} open port(s) found"))

    for port in known:
        lines = render_service(port, args.target, md)
        all_lines.extend(lines)
        if not md:
            for l in lines:
                print(l)

    unk_lines = render_unknown(unknown, md)
    all_lines.extend(unk_lines)
    if not md:
        for l in unk_lines:
            print(l)
        print()

    if args.output:
        out = Path(args.output)
        out.write_text("\n".join(all_lines) + "\n")
        if not md:
            print(c(GREEN, f"  Saved to {out}"))
            print()
        else:
            print(c(GREEN, f"\n  Saved markdown report to {out}\n"))


if __name__ == "__main__":
    main()
