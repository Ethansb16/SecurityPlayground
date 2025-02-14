from bcrypt import checkpw
from nltk.corpus import words
import time
from collections import defaultdict
from multiprocessing import Pool, cpu_count
import ssl
import nltk

def load_wordlist():
    print("Loading wordlist...")
    return [word for word in words.words() if 6 <= len(word) <= 10]

def parse_line(entry):
    try:
        username, hash_part = entry.strip().split(":")
        parts = hash_part.split("$")
        if len(parts) >= 4:
            work_factor = parts[2]
            hash_value = parts[3]
            return work_factor, hash_part 
    except Exception:
        return None

def check_password(args):
    word, full_hash = args
    try:
        if checkpw(word.encode('utf-8'), full_hash.encode('utf-8')):
            return full_hash, word
    except ValueError:
        pass
    return None

def crack_hash(hashed_pws):
    start_time = time.time()
    wordlist = load_wordlist()
    cracked_passwords = {}
    
    for work_factor_group in hashed_pws:
        work_factor = work_factor_group[0]
        hashes = work_factor_group[1:]
        
        task_list = []
        for full_hash in hash: 
            for word in wordlist:
                if len(word) > 0:
                    task_list.append((word, full_hash))
        
        total_combinations = len(task_list)
        print(f"\nTrying passwords for work factor {work_factor}...")
        print(f"Testing {len(wordlist)} words against {len(hashes)} hashes = {total_combinations} combinations")
        
        counter = 0
        last_update = time.time()
        update_interval = 2 
        
        with Pool(processes=cpu_count()) as pool:
            for result in pool.imap_unordered(check_password, task_list):
                counter += 1
                current_time = time.time()
                if current_time - last_update >= update_interval:
                    percentage = (counter / total_combinations) * 100
                    elapsed_time = current_time - start_time
                    print(f"Progress: {percentage:.1f}% completed ({counter}/{total_combinations}) - Time elapsed: {elapsed_time:.1f}s", end='\r')
                    last_update = current_time
                
                if result:
                    cracked_passwords[result[0]] = result[1]
                    print(f"\nPassword cracked! Found: {result[1]}")
    
    end_time = time.time()
    
    print("\n\nCracked Passwords:")
    for hash_val, password in cracked_passwords.items():
        print(f"{hash_val} -> {password}")
    print(f"\nTotal Execution Time: {end_time - start_time:.2f} seconds")

def main():
    try:
        nltk.download('words')
    except:
        pass

    try:
        with open("shadow.txt", "r") as file:
            lines = file.readlines()
    except FileNotFoundError:
        print("Error: shadow.txt not found.")
        return
    
    hashed_pw_list = [x for x in (parse_line(line) for line in lines) if x is not None]
    
    if not hashed_pw_list:
        print("No valid hashes found in file.")
        return
        
    grouped = defaultdict(list)
    for key, hash_value in hashed_pw_list:
        grouped[key].append(hash_value)
    
    collapsed_list = [[key] + passwords for key, passwords in grouped.items()]
    crack_hash(collapsed_list)

if __name__ == "__main__":
    main()