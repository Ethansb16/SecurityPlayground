from Crypto.Random import random, get_random_bytes
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


iv = get_random_bytes(AES.block_size)

def power(a, b, p): 
    return pow(a, b, p)

def generate_private_key(a): 
    return random.randint(1, a-1)

def generate_public_key(private_key, q, a): 
    return pow(a, private_key) % q

def compute_shared_secret(their_public_key, private_key, q):
    return pow(their_public_key, private_key) % q

def send_message(original_message, iv, sender_key,  reciever_key):
    """Simulates sending a message between users with """
    message = pad(original_message, AES.block_size)
    cipher = AES.new(sender_key, AES.MODE_CBC, iv=iv)
    encryption = cipher.encrypt(message)
    print(f"encrypted message: {original_message} -> {encryption}")
    cipher = AES.new(reciever_key, AES.MODE_CBC, iv= iv)
    return unpad(cipher.decrypt(encryption), AES.block_size)

def main(): 
    alpha = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)

    q = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
    
    print(f"value of q: {q}")
    print(f"value of alpha: {alpha}")

    #alice keys
    XA = generate_private_key(q)

    #modified
    YA = q

    print(f"alice private key: {XA}")
    print(f"alice public key: {YA}")

    #bob keys
    XB = generate_private_key(q)

    #modified
    YB = q

    print(f"bob public key: {XB}")
    print(f"bob private key: {YB}")

    #shared key
    k_alice = power(YB, XA, q)
    k_bob = power(YA, XB, q)
    print(f"alice shared key: {k_alice}")
    print(f"bob shared key: {k_bob}")

    sha_alice = sha256(str(k_alice).encode()).digest()[:16]
    sha_bob = sha256(str(k_bob).encode()).digest()[:16]
    
    m0 = b'Hi Alice!'
    m1 = b'Hi Bob!'
    
    print("Intercepted messages")
    print(send_message(m0, iv, sha_bob, sha_alice))
    print(send_message(m1, iv, sha_bob, sha_alice))

if __name__ == "__main__": 
    main()
