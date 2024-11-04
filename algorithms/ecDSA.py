import time
from ecdsa import SigningKey, NIST256p
from Crypto.Hash import SHA256

def ecdsa_metrics(input):
    print("\n### ECDSA ###")
    
    # Generate parameters
    print("# Generating parameters...")
    key = SigningKey.generate(curve=NIST256p)
    pubKey = key.get_verifying_key()
    
    # Signing
    print("# Signing...")
    startTime = time.perf_counter()
    
    digest = SHA256.new(str.encode(input)).digest()
    sig = key.sign_digest(digest)
    
    endTime = time.perf_counter()
    timeTaken = endTime - startTime
    signatureLength = len(sig)
    
    # Verification
    print("# Verifying...")
    verified = pubKey.verify_digest(sig, digest)

    if verified:
        print("# Signature is valid")
    else:
        print("# Signature is invalid")
    
    print(f"Signature length: {signatureLength} bytes")
    print(f"Time taken to generate the signature: {timeTaken} seconds")
    