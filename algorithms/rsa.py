import time
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from sympy import isprime

def sign(input, d, n):
    print("# Signing...")
    digest = int(SHA256.new(str.encode(input)).hexdigest(), 16)
    print("digest: ", digest)
    signature = pow(digest, d, n)
    
    return signature

def verify(input, signature, e, n):
    print("# Verifying...")
    digest = int(SHA256.new(str.encode(input)).hexdigest(), 16)
    plainText = pow(signature, e, n)
    print("plainText: ", plainText)
    
    return plainText == digest

def rsa_metrics(input):
    print("\n### RSA ###")
    
    # Generate parameters (p,q,n,e,d,phi)
    # p,q,phi,d are private
    print("# Generating parameters...")
    key = RSA.generate(2048) # 2048 is the key size
    assert isprime(key.p) is True
    assert isprime(key.q) is True
    
    # Signing
    startTime = time.perf_counter()
    
    signature = sign(input, key.d, key.n)
    
    endTime = time.perf_counter()
    timeTaken = endTime - startTime
    signatureLength = len(signature.to_bytes((signature.bit_length() + 7) // 8))
    
    # Verification
    verified = verify(input, signature, key.e, key.n)
    if verified:
        print("# Signature is valid")
    else:
        print("# Signature is invalid")
    
    print(f"Signature length: {signatureLength} bytes")
    print(f"Time taken to generate the signature: {timeTaken} seconds")
    