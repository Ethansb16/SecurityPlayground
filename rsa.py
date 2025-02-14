from Crypto.Util.number import getPrime

def mod_power(base, exponent, modulus):
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 ==1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base*base) % modulus

    return result


def mod_inverse(a,m):
    def egcd(a,b):
        if a ==0: return (b,0,1)
        else:
            g, y, x = egcd(b%a, a)
            return (g, x -(b//a) * y, y)
        
    g, x, _ = egcd(a, m)
    if g != 1: raise Exception('Modular inverse does not exist')
    else: return x % m

def int_ascii(num):
    return bytes.fromhex(hex(num)[2:])
        

if __name__ == '__main__':
    print('Task 1')
    # Get your prime numbers
    p = getPrime(2048)
    q = getPrime(2048)
    while q == p:
        q = getPrime(2048)
    
    # Setup necessary variables
    n = p * q
    phi = (p-1) * (q-1)
    e = 65537
    d = mod_inverse(e, phi)

    # Public and private keys
    PU = (e, n)
    PR = (d,n)

    # Encrypt desired message using Bob's public key
    M = 'Hello Bob!'
    print('Alice is sending message:', M)
    int_M = int(M.encode().hex(), 16)
    C = mod_power(int_M, e, n)
    print('Message', int_M)

    # Bob decrypts Alice's message with his private key
    D = mod_power(C, d, n)
    M2 = int_ascii(D)
    print('Bob recieved message:', M2)
    print('\n')
    
    print('Task 2')

    # Alice encrypts her message
    M = 'How are you doing Bob?'
    print('Alice is sending message:', M)
    int_M = int(M.encode().hex(), 16)
    C = mod_power(int_M, e, n)

    # Mallory recieves the cipher and changes it to C_prime
    r = 2
    C_prime = (C * mod_power(r, e, n)) % n
    print('C_prime: ',C_prime)

    # Mallory sends C_prime to Bob
    D = mod_power(C_prime, d, n)
    M2 = int_ascii(D)
    print('Bob recieved message:', M2)

    # Result recieved is
    print('Mallory could decrypt:', int_ascii(D//2))

    M1 = 'Hello Bob'
    int_M1 = int(M1.encode().hex(), 16)
    S1 = mod_power(int_M1, e, n)

    M2 = 'How are you doing Bob'
    int_M2 = int(M2.encode().hex(), 16)
    S2 = mod_power(int_M2, e, n)
    print(S1, S2)

    S3 = (S1 * S2) % n
    D3 = mod_power(S3, d, n)
    M3 = int_ascii(D3)
    S4 = mod_power(int(M3.hex(), 16), e, n)

    print('S3 -S4', S3 - S4)
    
