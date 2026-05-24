#!/usr/bin/env python3
"""Sanitize a RouterOS .rsc export for public sharing."""
import re, sys

def sanitize_rsc(inpath, outpath):
    with open(inpath) as f:
        content = f.read()
    
    # Add sanitization header
    header = "# Sanitized for public sharing — original credentials, MACs, and identifiers replaced\n"
    
    # Replace PPPoE username (email-like pattern after user=)
    # Handle both inline values and continued lines (user=\n    value)
    content = re.sub(
        r'user=\\\n\s*\S+@\S+',
        'user=pppoe-user@isp.example.com',
        content
    )
    content = re.sub(
        r'user=[^\s]+',
        'user=pppoe-user@isp.example.com',
        content
    )
    
    # Replace MAC addresses (xx:xx:xx:xx:xx:xx format)
    content = re.sub(
        r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',
        lambda m: m.group(0) if m.group(0).startswith(('FF', 'ff')) else 'xx:xx:xx:xx:xx:xx',
        content
    )
    
    # Replace serial number
    content = re.sub(
        r'serial number = \S+',
        'serial number = [REDACTED]',
        content
    )
    
    # Replace software ID
    content = re.sub(
        r'software id = \S+',
        'software id = [REDACTED]',
        content
    )
    
    # Replace password-like values (psk, secret, password, passphrase)
    content = re.sub(
        r'(password|secret|passphrase|pre-shared-key|wpa2-pre-shared-key|api-secret)=\S+',
        r'\1=[REDACTED]',
        content
    )
    
    # Replace IP addresses that look like public IPs (not RFC1918)
    content = re.sub(
        r'\b(?!10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)(\d{1,3}\.){3}\d{1,3}\b',
        'xxx.xxx.xxx.xxx',
        content
    )
    
    content = header + content
    with open(outpath, 'w') as f:
        f.write(content)
    
    print(f"Sanitized: {inpath} → {outpath}")
    lines = content.count('\n')
    print(f"Output: {lines} lines")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: sanitize_rsc.py input.rsc output.rsc")
        sys.exit(1)
    sanitize_rsc(sys.argv[1], sys.argv[2])
