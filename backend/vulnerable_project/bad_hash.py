import hashlib
import ssl

def legacy_hash(data):
    # Triggers MD5 rule
    return hashlib.md5(data.encode()).hexdigest()

def insecure_connection():
    # Triggers Weak TLS rule
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    return context