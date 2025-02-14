import time
import hashlib
import random
import string
from matplotlib import pyplot as plt

def sha256_hash(data):
    hash_object = hashlib.sha256(data.encode())
    return hash_object.hexdigest()

def random_string(length=10):
    chars = string.ascii_letters + string.digits  # a-z, A-Z, 0-9
    return ''.join(random.choice(chars) for _ in range(length))

def find_collision():

    bit_range = [i for i in range(8, 49, 4)]
    elapsed_times = []
    counts = []
    for bits in bit_range:
        start_time = time.time()
        count = 0
        seen_hashes = {}
        print(f"Searching for a collision with {bits} bits...")
        while True:

            count += 1
            rand_str = random_string()
            truncated_hash = sha256_hash(rand_str)[:(bits//4)]
            if seen_hashes.get(truncated_hash):
                end_time = time.time()
                print(f"Collision found!")
                print(f"String 1: {seen_hashes[truncated_hash]} -> {truncated_hash}")
                print(f"String 2: {rand_str} -> {truncated_hash}")
                elapsed_times.append(end_time - start_time)
                counts.append(count)
                break

            seen_hashes[truncated_hash] = rand_str
    return bit_range, elapsed_times, counts


def hamming_dist(first, second): 
    hamming_distance = sum(b1 != b2 for b1, b2 in zip(first, second))
    return hamming_distance
        

def main():
    user_input = input("Enter text to hash: ")
    hashed_output = sha256_hash(user_input)

    print(f" 1a) SHA-256 Digest: {hashed_output}")
    check_hamming_dist = sha256_hash("distance check")
    print(f"2a) {hamming_dist(hashed_output, check_hamming_dist)}")

    bit_range, elapsed_times, counts = find_collision()
    fig, (ax1,ax2) = plt.subplots(1,2)
    ax1.plot(bit_range, elapsed_times, marker='o', linestyle='-', color='b', linewidth=2, label = 'Data Line')
    ax1.set_xlabel('Digest size (bits)')
    ax1.set_ylabel('Time till collision')
    ax1.set_title("Digest size vs Collision Time")
    ax1.legend()

    ax2.plot(bit_range, counts, marker='x', linestyle='-', color='r', linewidth=2, label = 'Data Line')
    ax2.set_xlabel('Digest size (bits)')
    ax2.set_ylabel('Total inputs')
    ax2.set_title("Digest size vs Total inputs")
    ax2.legend()
    plt.show()

if __name__ == "__main__":
    main()