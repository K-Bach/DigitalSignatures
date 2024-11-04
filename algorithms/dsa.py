import time
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256
from sympy import isprime
import random

def sign(input, q, g, p, x):
    print("# Signing...")
    
    digest = SHA256.new(str.encode(input)).digest()
    k = random.randint(1, q - 1)
    r = pow(g, k, p) % q
    s = (pow(k, -1, q) * ((int.from_bytes(digest) % q) + x * r)) % q

    while r == 0 or s == 0:
        k = random.randint(1, q - 1)
        r = pow(g, k, p) % q
        s = (pow(k, -1, q) * ((int.from_bytes(digest) % q) + x * r)) % q
    print("r: ", r)
    
    return s, r

def verify(input, s, r, q, g, p, y):
    print("# Verifying...")
    
    w = pow(s, -1, q)
    digest = SHA256.new(str.encode(input)).digest()
    u1 = (int.from_bytes(digest) * w) % q
    u2 = (r * w) % q
    v = (pow(g, u1, p) * pow(y, u2, p)) % p % q
    print("v: ", v)
    
    return v == r

def dsa_metrics(input):
    print("\n### DSA ###")
    
    # Generate public parameters (p,q,g)
    print("# Generating parameters...")
    key = DSA.generate(2048) # 2048 is the key size

    assert isprime(key.p) is True
    assert isprime(key.q) is True

    #Signing (r,s)
    start_time = time.perf_counter()

    s, r = sign(input, key.q, key.g, key.p, key.x)

    end_time = time.perf_counter()
    time_taken = end_time - start_time
    signature_length = len(r.to_bytes((r.bit_length() + 7) // 8)) + len(s.to_bytes((s.bit_length() + 7) // 8))

    #Verification
    verified = verify(input, s, r, key.q, key.g, key.p, key.y)

    if verified:
        print("# Signature is valid")
    else:
        print("# Signature is invalid")
        
    print(f"Signature length: {signature_length} bytes")
    print(f"Time taken to generate the signature: {time_taken} seconds")
