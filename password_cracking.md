# Password Cracking Notes (CTF Focused)

## Educational Use
This document is intended for educational and training purposes only. All examples and workflows are derived from old Capture The Flag challenges or intentionally vulnerable lab environments.

---

## General Strategy
- Identify the hash or encoding type before attacking
- Always check for encoding before assuming hashing
- Start with fast wins using known wordlists and online tools
- Use John the Ripper for flexibility and automation
- Use Hashcat for speed, masks, and advanced attacks
- Escalate complexity only when simple attacks fail

---

## Hash Identification

Correctly identifying the hash type prevents wasted attacks.

### Online Tools
- https://www.tunnelsup.com/hash-analyzer/  
  Analyze structure, delimiters, and encoding.

- https://hashes.com/en/tools/hash_identifier  
  Fast identifier supporting many formats.

### Command Line
```
hashid <hash>
```
- Quickly suggests possible hash formats
- Useful for confirming guesses before choosing attack modes

---

## Hashing (Easy)

These challenges involve generating hashes, not cracking them.

### Examples
MD5 of sunny0797dday  
90279ff010515bbc637bac7ed06e58ac

SHA1 of 9580OceanBreeze  
b95f61100508f866a46f68f9f68249220dcb61eb

SHA256 of 236fastcar872  
211e07669a4ac9e3a4ca3dfbc878acfb5ec607c29993d15a86d683e585f0ed3a

### Notes
- MD5, SHA1, and SHA256 are deterministic
- Useful for verification and challenge setup

---

## Hash Resources

Used for identification, verification, and quick wins.

### Online Tools
- https://crackstation.net/  
  Fast lookup for weak and common hashes.

- https://www.tunnelsup.com/hash-analyzer/  
  Structure and hash analysis.

- https://hashes.com/en/decrypt/hash  
  Community driven cracking database.

- https://www.md5hashgenerator.com/  
  Generate hashes for testing and verification.

### Notes
- Best for quick checks, not sustained cracking
- Always validate results locally when possible

---

## Wordlists

Wordlists are the foundation of most cracking attacks.

### Primary Resource
- https://github.com/danielmiessler/SecLists  

Contains curated lists for:
- Passwords
- Usernames
- Directory and file brute forcing
- Fuzzing and parameter discovery

### Notes
- Start with rockyou.txt for fast wins  
- Use context specific lists whenever possible  
- Smaller targeted lists outperform massive generic ones  

---

## Windows Passwords (NTLM)

Windows hashes can often be cracked offline.

### Tool Used
Ophcrack

Installed tables:
- XP free fast
- XP free small
- Vista free

### Notes
- NT Pwd column contains plaintext passwords
- Effective only against weak or legacy passwords

---

## Pattern Based Cracking (Mask Attacks)

Used when part of the password format is known.

### Example
```
hashcat -m 500 -a 3 hash.txt 'PREFIX-MASK-?d?d?d?d'
```

### Breakdown
- `-m 500` md5crypt
- `-a 3` mask attack
- `?d` numeric charset
- `?d?d?d?d` four unknown digits

### Notes
- Masks dramatically reduce keyspace
- Use only when structure is known

---

## ZIP Password Cracking

Encrypted archives are common in CTFs.

### Workflow
```
zip2john encrypted.zip > encrypted.txt
john encrypted.txt
unzip -P <password> encrypted.zip
```

### Notes
- John handles ZIP formats reliably
- Switch to Hashcat if cracking is slow

---

## Practical Takeaways
- Identification comes before cracking
- Decode first, crack second
- Start simple and escalate
- Speed and accuracy win CTFs
