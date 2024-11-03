import time
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA1
from sympy import isprime

def sign(input, key):
    print("# Signing...")
    digest = int(SHA1.new(str.encode(input)).hexdigest(), 16)
    print("digest: ", digest)
    signature = pow(digest, key.d, key.n)
    print("signature: ", signature)
    return signature

def verify(input, signature, key):
    print("# Verifying...")
    digest = int(SHA1.new(str.encode(input)).hexdigest(), 16)
    print("digest: ", digest)
    plainText = pow(signature, key.e, key.n)
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
    
    signature = sign(input, key)
    
    endTime = time.time()
    timeTaken = endTime - startTime
    signatureLength = len(signature.to_bytes((signature.bit_length() + 7) // 8))
    
    # Verification
    verified = verify(input, signature, key)
    if verified:
        print("# Signature is valid")
    else:
        print("# Signature is invalid")
    
    print(f"Signature length: {signatureLength} bytes")
    print(f"Time taken to generate the signature: {timeTaken} seconds")
    