import time
from Crypto.PublicKey import DSA
from sympy import isprime
import random
import hashlib

input = input("Enter a string: ")

# Generate parameters (p,q,g)
key = DSA.generate(3072) # 3072 is the key size
p, q = key.p, key.q

assert isprime(p) is True
assert isprime(q) is True

h = random.randint(2, p - 2)
g = pow(h, (p - 1) // q, p)

while g == 1:
    h = random.randint(2, p - 2)
    g = pow(h, (p - 1) // q, p)
    
# Generate key pair (x,y)
x = random.randint(1, q - 1) # private key
y = pow(g, x, p) # public key

#Signing (r,s)
start_time = time.time()

digest = hashlib.sha1(str.encode(input)).digest()
k = random.randint(1, q - 1)
r = pow(g, k, p) % q
s = (pow(k, -1, q) * ((int.from_bytes(digest) % q) + x * r)) % q

while r == 0 or s == 0:
    k = random.randint(1, q - 1)
    r = pow(g, k, p) % q
    s = (pow(k, -1, q) * ((int.from_bytes(digest) % q) + x * r)) % q

end_time = time.time()
time_taken = end_time - start_time

signature_length = len(r.to_bytes((r.bit_length() + 7) // 8)) + len(s.to_bytes((s.bit_length() + 7) // 8))

# computational_cost = 

#Verification
w = pow(s, -1, q)
u1 = (int.from_bytes(digest) * w) % q
u2 = (r * w) % q
v = (pow(g, u1, p) * pow(y, u2, p)) % p % q

if v == r:
    print("Signature is valid")
else:
    print("Signature is invalid")
    
print(f"Signature length: {signature_length} bytes")
print(f"Time taken to generate the signature: {time_taken} seconds")
# print(f"Computational cost: {computational_cost} operations")