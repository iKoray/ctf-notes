# Nmap Cheat Sheet (CTF Focused)

## Purpose
Nmap is a network discovery and port scanning tool used to identify live hosts, open ports, running services, versions, and potential vulnerabilities. It is almost always the first step in enumeration during a CTF or lab.

---

## Basic Syntax
```
nmap [options] <target>
```

### Target Formats
- Single IP: `10.10.10.10`
- Hostname: `example.com`
- CIDR: `10.10.10.0/24`
- Multiple targets: `10.10.10.5 10.10.10.6`

---

## Host Discovery
Used to determine whether a host is alive before scanning ports.

```
-sn    Ping scan only, no port scan
-Pn    Skip host discovery, assume host is up
```

CTF note: Always use `-Pn` on Hack The Box or TryHackMe. ICMP is usually blocked.

---

## Port Scanning
```
-p 80          Scan a specific port
-p 1-1000      Scan a port range
-p-            Scan all 65,535 ports
--top-ports 1000
```

Common CTF practice:
```
nmap -p- --min-rate 1000 <target>
```

---

## Scan Types
```
-sS    TCP SYN scan (stealth, requires sudo)
-sT    TCP connect scan (no sudo)
-sU    UDP scan (very slow)
-sA    ACK scan (firewall detection)
-sN    TCP Null scan
-sF    TCP FIN scan
-sX    Xmas scan
```

CTF guidance:
- Use `-sS` whenever possible
- Use `-sU` only when UDP services are suspected

---

## Service and Version Detection
```
-sV    Detect service versions
```

Example:
```
nmap -sV -p 22,80 <target>
```

---

## OS Detection
```
-O     OS detection
```

Requires sudo and at least one open port.

---

## Script Scanning (NSE)
```
-sC                 Run default safe scripts
--script=<name>
--script=<category>
--script-args=<args>
```

### Common Script Categories
- default
- vuln
- auth
- discovery
- exploit

### Examples
```
nmap -sC <target>
nmap --script vuln <target>
nmap --script http-enum <target>
```

`nmap --script vuln` checks for common vulnerabilities. NSE scripts can also be extended with custom or third party scripts to target specific services or CVEs.

---

## Output Formats
Always save your scans.

```
-oN scan.txt     Normal human readable output
-oG scan.gnmap   Grepable output
-oX scan.xml     XML output
-oA scan         All formats
```

---

## Timing and Performance
```
-T0 to T5        Timing templates
--min-rate 1000
--max-retries 3
--host-timeout 5m
```

### Timing Levels
- `-T0` Paranoid. Extremely slow. IDS evasion.
- `-T1` Sneaky. Very slow.
- `-T2` Polite. Reduced network load.
- `-T3` Normal. Default.
- `-T4` Aggressive. Fast and noisy.
- `-T5` Insane. Very fast, may miss results.

CTF note: Higher timing equals more noise. This does not matter in CTFs. In real assessments, aggressive timing would draw attention.

---

## My Go To Scan
```
nmap <IP> -p- -sVC -oN scan.txt -T4
```

### Explanation
- `-p-` scans all 65,535 ports
- `-sV` detects service versions
- `-sC` runs default scripts for common info and vulnerabilities
- `-oN` saves output in readable format
- `-T4` speeds up the scan for CTF use

---

## Common CTF Scans

### Fast Full Port Scan
```
sudo nmap -p- -T4 --min-rate 1000 -Pn <target>
```

### Service and Script Scan on Discovered Ports
```
sudo nmap -sC -sV -p <ports> <target>
```

### Vulnerability Scan
```
nmap --script vuln -p <ports> <target>
```

### Targeted UDP Scan
```
sudo nmap -sU -p 53,161 <target>
```

---

## Practical Notes
- Always scan all ports first
- Rerun `-sC -sV` only on discovered ports
- Service versions matter more than port numbers
- NSE output often reveals paths, credentials, or misconfigurations
- Nmap output feeds tools like Gobuster, Nikto, and Metasploit
