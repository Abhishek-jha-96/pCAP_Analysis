import hashlib
import os

def file_hash(file_path, algorithm='sha256'):
    """
    Calculate hash of a file
    
    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use (default: sha256)
    
    Returns:
        Hexadecimal hash string
    """
    hash_obj = hashlib.new(algorithm)
    
    try:
        with open(file_path, 'rb') as f:
            # Read file in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except FileNotFoundError:
        return "File not found"
    except Exception as e:
        return f"Error: {str(e)}"

def format_bytes(bytes_val):
    """Format bytes into human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} TB"

def is_private_ip(ip):
    """Check if an IP address is in private range"""
    return (ip.startswith('192.168.') or 
            ip.startswith('10.') or 
            ip.startswith('172.16.') or
            ip.startswith('127.') or
            ip == 'localhost')

def extract_domain_from_url(url):
    """Extract domain from URL"""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url if url.startswith('http') else f'http://{url}')
        return parsed.netloc.lower()
    except:
        return url