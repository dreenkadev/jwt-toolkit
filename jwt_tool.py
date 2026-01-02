#!/usr/bin/env python3
"""
JWT Toolkit - JWT analysis and manipulation

Features:
- JWT decoding
- Signature verification
- Algorithm confusion testing
- Brute force secrets
- Token generation
- Claim analysis
"""

import argparse
import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

VERSION = "1.0.0"

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


def b64_decode(data: str) -> bytes:
    """Base64 URL decode"""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def b64_encode(data: bytes) -> str:
    """Base64 URL encode"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


class JWTToolkit:
    def __init__(self):
        self.header = {}
        self.payload = {}
        self.signature = b''
        self.raw_token = ''
        
    def decode(self, token: str) -> Dict:
        """Decode JWT without verification"""
        self.raw_token = token
        parts = token.split('.')
        
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        
        try:
            self.header = json.loads(b64_decode(parts[0]))
            self.payload = json.loads(b64_decode(parts[1]))
            self.signature = b64_decode(parts[2])
        except Exception as e:
            raise ValueError(f"Failed to decode: {e}")
        
        return {
            'header': self.header,
            'payload': self.payload,
            'signature': self.signature.hex()
        }
    
    def verify(self, token: str, secret: str) -> bool:
        """Verify JWT signature"""
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        header = json.loads(b64_decode(parts[0]))
        alg = header.get('alg', '')
        
        if alg == 'HS256':
            expected = self.sign_hs256(parts[0], parts[1], secret)
            return expected == parts[2]
        elif alg == 'HS384':
            expected = self.sign_hs384(parts[0], parts[1], secret)
            return expected == parts[2]
        elif alg == 'HS512':
            expected = self.sign_hs512(parts[0], parts[1], secret)
            return expected == parts[2]
        elif alg == 'none':
            return parts[2] == ''
        
        return False
    
    def sign_hs256(self, header_b64: str, payload_b64: str, secret: str) -> str:
        """Sign with HS256"""
        message = f"{header_b64}.{payload_b64}".encode()
        signature = hmac.new(secret.encode(), message, hashlib.sha256).digest()
        return b64_encode(signature)
    
    def sign_hs384(self, header_b64: str, payload_b64: str, secret: str) -> str:
        """Sign with HS384"""
        message = f"{header_b64}.{payload_b64}".encode()
        signature = hmac.new(secret.encode(), message, hashlib.sha384).digest()
        return b64_encode(signature)
    
    def sign_hs512(self, header_b64: str, payload_b64: str, secret: str) -> str:
        """Sign with HS512"""
        message = f"{header_b64}.{payload_b64}".encode()
        signature = hmac.new(secret.encode(), message, hashlib.sha512).digest()
        return b64_encode(signature)
    
    def generate(self, payload: Dict, secret: str, alg: str = 'HS256', 
                 expires_in: int = 3600) -> str:
        """Generate JWT"""
        header = {'typ': 'JWT', 'alg': alg}
        
        # Add standard claims
        now = int(time.time())
        payload['iat'] = now
        payload['exp'] = now + expires_in
        
        header_b64 = b64_encode(json.dumps(header).encode())
        payload_b64 = b64_encode(json.dumps(payload).encode())
        
        if alg == 'HS256':
            signature = self.sign_hs256(header_b64, payload_b64, secret)
        elif alg == 'HS384':
            signature = self.sign_hs384(header_b64, payload_b64, secret)
        elif alg == 'HS512':
            signature = self.sign_hs512(header_b64, payload_b64, secret)
        elif alg == 'none':
            signature = ''
        else:
            raise ValueError(f"Unsupported algorithm: {alg}")
        
        return f"{header_b64}.{payload_b64}.{signature}"
    
    def create_none_token(self, token: str) -> str:
        """Create 'none' algorithm token (for testing)"""
        parts = token.split('.')
        header = json.loads(b64_decode(parts[0]))
        header['alg'] = 'none'
        
        header_b64 = b64_encode(json.dumps(header).encode())
        return f"{header_b64}.{parts[1]}."
    
    def brute_force(self, token: str, wordlist: List[str]) -> Optional[str]:
        """Brute force secret"""
        for secret in wordlist:
            if self.verify(token, secret):
                return secret
        return None
    
    def analyze_claims(self, payload: Dict) -> List[Dict]:
        """Analyze JWT claims for security issues"""
        issues = []
        now = int(time.time())
        
        # Check expiration
        exp = payload.get('exp')
        if exp:
            if exp < now:
                issues.append({
                    'severity': 'info',
                    'title': 'Token expired',
                    'detail': f'Expired at {datetime.fromtimestamp(exp)}'
                })
            elif exp > now + 86400 * 365:
                issues.append({
                    'severity': 'medium',
                    'title': 'Very long expiration',
                    'detail': 'Token valid for over a year'
                })
        else:
            issues.append({
                'severity': 'high',
                'title': 'No expiration claim',
                'detail': 'Token never expires'
            })
        
        # Check for sensitive data
        sensitive_keys = ['password', 'secret', 'credit_card', 'ssn']
        for key in payload.keys():
            if any(s in key.lower() for s in sensitive_keys):
                issues.append({
                    'severity': 'high',
                    'title': 'Sensitive data in claims',
                    'detail': f'Claim "{key}" may contain sensitive data'
                })
        
        # Check admin/role claims
        if payload.get('admin') == True or payload.get('role') == 'admin':
            issues.append({
                'severity': 'info',
                'title': 'Admin privileges',
                'detail': 'Token has admin role'
            })
        
        return issues


def print_banner():
    print(f"""{Colors.CYAN}
      _ __        _______ 
     | |\\ \\      / /_   _|
  _  | | \\ \\ /\\ / /  | |  
 | |_| |  \\ V  V /   | |  
  \\___/    \\_/\\_/    |_|  
  _____           _ _    _ _   
 |_   _|__   ___ | | | _(_) |_ 
   | |/ _ \\ / _ \\| | |/ / | __|
   | | (_) | (_) | |   <| | |_ 
   |_|\\___/ \\___/|_|_|\\_\\_|\\__|
{Colors.RESET}                        v{VERSION}
""")


def print_decoded(decoded: Dict):
    """Print decoded token"""
    print(f"\n{Colors.BOLD}Header:{Colors.RESET}")
    print(f"  {json.dumps(decoded['header'], indent=2)}")
    
    print(f"\n{Colors.BOLD}Payload:{Colors.RESET}")
    
    # Format dates
    payload = decoded['payload'].copy()
    for key in ['iat', 'exp', 'nbf']:
        if key in payload:
            payload[key] = f"{payload[key]} ({datetime.fromtimestamp(payload[key])})"
    
    print(f"  {json.dumps(payload, indent=2)}")
    
    print(f"\n{Colors.BOLD}Signature:{Colors.RESET}")
    print(f"  {decoded['signature'][:40]}...")


def demo_mode():
    """Run demo"""
    print(f"{Colors.CYAN}Running demo...{Colors.RESET}")
    
    toolkit = JWTToolkit()
    
    # Generate sample token
    secret = "my_secret_key"
    payload = {
        'sub': '1234567890',
        'name': 'John Doe',
        'role': 'admin'
    }
    
    token = toolkit.generate(payload, secret, 'HS256')
    print(f"\n{Colors.BOLD}Generated Token:{Colors.RESET}")
    print(f"  {token[:50]}...")
    
    # Decode
    decoded = toolkit.decode(token)
    print_decoded(decoded)
    
    # Verify
    print(f"\n{Colors.BOLD}Signature Verification:{Colors.RESET}")
    valid = toolkit.verify(token, secret)
    if valid:
        print(f"  {Colors.GREEN}✓ Signature valid{Colors.RESET}")
    else:
        print(f"  {Colors.RED}✗ Signature invalid{Colors.RESET}")
    
    # Analyze
    print(f"\n{Colors.BOLD}Claim Analysis:{Colors.RESET}")
    issues = toolkit.analyze_claims(decoded['payload'])
    for issue in issues:
        color = Colors.RED if issue['severity'] == 'high' else Colors.YELLOW
        print(f"  {color}[{issue['severity'].upper()}]{Colors.RESET} {issue['title']}")
        print(f"    {issue['detail']}")


def main():
    parser = argparse.ArgumentParser(description="JWT Toolkit")
    parser.add_argument("token", nargs="?", help="JWT token")
    parser.add_argument("-d", "--decode", action="store_true", help="Decode token")
    parser.add_argument("-v", "--verify", metavar="SECRET", help="Verify with secret")
    parser.add_argument("-g", "--generate", metavar="SECRET", help="Generate token")
    parser.add_argument("-p", "--payload", help="Payload JSON for generation")
    parser.add_argument("--none", action="store_true", help="Create 'none' alg token")
    parser.add_argument("--demo", action="store_true", help="Run demo")
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.demo:
        demo_mode()
        return
    
    if not args.token and not args.generate:
        print(f"{Colors.YELLOW}No token specified. Use --demo for demonstration.{Colors.RESET}")
        return
    
    toolkit = JWTToolkit()
    
    if args.generate:
        payload = json.loads(args.payload) if args.payload else {'sub': 'user'}
        token = toolkit.generate(payload, args.generate)
        print(f"{Colors.BOLD}Generated Token:{Colors.RESET}")
        print(token)
        return
    
    if args.decode or args.token:
        decoded = toolkit.decode(args.token)
        print_decoded(decoded)
        
        # Analyze
        print(f"\n{Colors.BOLD}Claim Analysis:{Colors.RESET}")
        issues = toolkit.analyze_claims(decoded['payload'])
        if issues:
            for issue in issues:
                color = Colors.RED if issue['severity'] == 'high' else Colors.YELLOW
                print(f"  {color}[{issue['severity'].upper()}]{Colors.RESET} {issue['title']}")
        else:
            print(f"  {Colors.GREEN}No issues found{Colors.RESET}")
    
    if args.verify:
        valid = toolkit.verify(args.token, args.verify)
        print(f"\n{Colors.BOLD}Verification:{Colors.RESET}")
        if valid:
            print(f"  {Colors.GREEN}✓ Signature valid{Colors.RESET}")
        else:
            print(f"  {Colors.RED}✗ Signature invalid{Colors.RESET}")
    
    if args.none:
        none_token = toolkit.create_none_token(args.token)
        print(f"\n{Colors.BOLD}None Algorithm Token:{Colors.RESET}")
        print(f"  {none_token}")


if __name__ == "__main__":
    main()
