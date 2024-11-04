import time
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1
from sympy import isprime

def sign(input, d, n):
    print("# Signing...")
    digest = int(SHA1.new(str.encode(input)).hexdigest(), 16)
    print("digest: ", digest)
    signature = pow(digest, d, n)
    print("signature: ", signature)
    
    return signature

def verify(input, signature, e, n):
    print("# Verifying...")
    digest = int(SHA1.new(str.encode(input)).hexdigest(), 16)
    print("digest: ", digest)
    plainText = pow(signature, e, n)
    print("plainText: ", plainText)
    
    return plainText == digest

def rsa_metrics(input):
    print("\n### RSA ###")
    
    # Generate parameters (p,q,n,e,d,phi)
    # p,q,phi,d are private
    print("# Generating parameters...")
    key = RSA.generate(3072) # 3072 is the key size
    assert isprime(key.p) is True
    assert isprime(key.q) is True
    
    # Signing
    startTime = time.time()
    
    signature = sign(input, key.d, key.n)
    
    endTime = time.time()
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
    