#!/usr/bin/env python

#####################################################
# Pseudocode for SHA256 and SHA512 based on Wikipedia's article on
# SHA-2 hashing, and RFC-4634. Some python specific help was found
# from two stackoverflow threads.
# https://www.rfc-editor.org/rfc/rfc4634#page-6
# https://en.wikipedia.org/wiki/MD5
# https://en.wikipedia.org/wiki/SHA-2
# https://stackoverflow.com/questions/11937192/sha-256-pseuedocode
# https://stackoverflow.com/questions/7321694/sha-256-implementation-in-python
#####################################################
import sys
import os
import time

NUM_MD5 = 100
NUM_SHA256 = 100
NUM_SHA512 = 100

# Cracking info
ALPHA_LOWER = "abcdefghijklmonpqrstuvwxyz"
ALPHA_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
NUMERCAL = "0123456789"
SPECIAL = " !@#$%^&*()_-+=[]}{\\|;:\'\"<,>./?~`"

# Define MD5 constants
MD5_W = 32
MD5_RUNS = 64
MD5_FF = 0xffffffff
MD5_INIT = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
MD5_S = [7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
         5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
         4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
         6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21]
MD5_K = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391]

# Define SHA256 and SHA512 constants (square and cube roots of primes)
SHA256_H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
SHA512_H = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 
            0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
SHA256_K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
SHA512_K = [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
            0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
            0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
            0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
            0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
            0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
            0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
            0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
            0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
            0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
            0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
            0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
            0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817]
SHA256_W = 32
SHA512_W = 64
SHA256_RUNS = 64
SHA512_RUNS = 80
SHA256_SIGMAS = {"s0": [7, 18, 3], "s1": [17, 19, 10], "b0": [2, 13, 22], "b1": [6, 11, 25]}
SHA512_SIGMAS = {"s0": [1, 8, 7], "s1": [19, 61, 6], "b0": [28, 34, 39], "b1": [14, 18, 41]}
SHA256_FF = 0xffffffff
SHA512_FF = 0xffffffffffffffff

# Main. Allows for encoding or decoding input using various hashing methods.
def main():
    sel = int(get_input_option(
        "Select mode:\n[0]: Encode\n[1]: Decode", 
        "number in range [0, 1]", ["0", "1"]))
    mode = int(get_input_option(
        "Select hashing mode:\n[0]: Custom\n[1]: MD5\n[2]: SHA-256\n[3]: SHA-512", 
        "number in range [0, 3]", ["0", "1", "2", "3"]))
    match sel:
        case 0:
            value = input("Enter value to hash: ")
            print(encode(value, mode))
        case 1:
            value = input("Enter hash to decode: ")
            print(decode(value, mode))
    check_hashes()
    return

# Encodes the given value using the given mode
def encode(value: str, mode: int):
    value = byte_encode(value)
    match mode:
        case 0:
            return custom_hash(value, False).hex()
        case 1:
            return md5(value).hex()
        case 2:
            return sha256(value).hex()
        case 3:
            return sha512(value).hex()
    return ""

# Decodes the given value using the given mode.
def decode(value: str, mode: int):
    method = int(get_input_option(
        "Select method:\n[0]: Wordlist\n[1]: Bruteforce",
        "number in range [0, 1]", ["0", "1"]))
    
    match method:
        case 0:
            # Wordlist
            file = get_input_file("Password file to use: ")
            return decode_wordlist(value, mode, file)
        case 1:
            # Bruteforce
            pass_min = get_input_number("Min length: ", "number")
            pass_max = get_input_number("Max length: ", "number")
            use_alpha_l = int(get_input_option(
                "Allow lowercase letters?\n[1]: Yes\n[0]: No",
                "number in range [0, 1]", ["0", "1"]))
            use_alpha_u = int(get_input_option(
                "Allow uppercase letters?\n[1]: Yes\n[0]: No",
                "number in range [0, 1]", ["0", "1"]))
            use_numbers = int(get_input_option(
                "Allow numbers?\n[1]: Yes\n[0]: No",
                "number in range [0, 1]", ["0", "1"]))
            use_special = int(get_input_option(
                "Allow special characters?\n[1]: Yes\n[0]: No",
                "number in range [0, 1]", ["0", "1"]))
            
            # Get allowed characters
            allowed_chars = ""
            if use_numbers == 1:
                allowed_chars += NUMERCAL
            if use_alpha_l == 1:
                allowed_chars += ALPHA_LOWER
            if use_alpha_u == 1:
                allowed_chars += ALPHA_UPPER
            if use_special == 1:
                allowed_chars += SPECIAL
            return decode_bruteforce(value, mode, allowed_chars, pass_min, pass_max)
    return "Decoding failed: invalid input."

# Decodes the given hash using the given wordlist
def decode_wordlist(value: str, mode: int, file: str):
    start = time.time()
    count = 0
    with open(file, 'r', encoding='utf-8') as file_obj:
        for line in file_obj:
            cur_pass = line.rstrip()
            count += 1
            #print("[{}]: [{}]".format(count, cur_pass))
            if encode(cur_pass, mode) == value:
                end = time.time()
                print("Found match in {time} seconds: {result}".format(time=(end - start), result=cur_pass))
                return cur_pass
    file_obj.close()
    return "Could not decode hash"

# Bruteforce decodes the given hash using the requested mode
def decode_bruteforce(value: str, mode: int, allowed_chars: str, min_len: int, max_len: int):
    cur_pass = ""

    # Estimate time to run code
    start = time.time()
    if encode(cur_pass, mode) == value:
        return cur_pass
    end = time.time()
    num_iterations = 0
    for i in range(min_len, max_len+1):
        num_iterations += len(allowed_chars) ** i
    time_estimate = num_iterations * (end - start)
    print("Attempting decode with {mode}. Required iterations: {num_iterations}, Estimated time: {time_estimate:.3f} seconds..."
          .format(mode=(get_mode(mode)), num_iterations=num_iterations, time_estimate=time_estimate))

    # Attempt all legal combinations of characters
    loop_start = time.time()
    for pass_len in range(min_len, max_len+1):
        print("Attempting length {pass_len}...".format(pass_len=pass_len))
        index = [0] * pass_len
        cur_pass = "".join(allowed_chars[0] for i in range(pass_len))
        options_left = True
        start = time.time()
        while options_left:
            # Set current password to be a representation of the current indices
            pass_text = list(cur_pass)
            for i in range(len(index)):
                pass_text[i] = allowed_chars[index[i]]
            cur_pass = "".join(pass_text)
            # If the current guess matches the expected hash, return it
            if encode(cur_pass, mode) == value:
                end = time.time()
                print("Found match in {time} seconds: {result}".format(time=(end - loop_start), result=cur_pass))
                return cur_pass
            # If the password does not match, increment indices until they run out
            options_left = False
            for i in range(pass_len):
                if index[i] + 1 < len(allowed_chars):
                    index[i] += 1
                    options_left = True
                    break
                else:
                    index[i] = 0
                    if i + 1 >= pass_len:
                        end = time.time()
                        print("Attempting last character {char}. Time passed this iteration: {time:.3f}"
                              .format(char=allowed_chars[index[i]+1], time=(end-start)))
                        start = time.time()
    return "Could not decode hash"

# Returns the name of the hashing mode requested
def get_mode(mode: int):
    match mode:
        case 0:
            return "custom hash"
        case 1:
            return "md5"
        case 2:
            return "sha256"
        case 3:
            return "sha512"

# Checks if the hashing algorithms match their expected output
def check_hashes():
    print("Running checks...")
    checkMD5 = md5("abc").hex()
    check256 = sha256("abc").hex()
    check512 = sha512("abc").hex()
    checkCustom1 = custom_hash("UFL", False).hex()
    checkCustom2 = custom_hash("security", False).hex()
    checkCustom3 = custom_hash("rampazzi", False).hex()
    print("Is MD5 correct: " + str(checkMD5 == "900150983cd24fb0d6963f7d28e17f72"))
    print("Is SHA-256 correct: " + str(check256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))
    print("Is SHA-512 correct: " + str(check512 == "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"))
    print("Is Custom1 correct: " + str(checkCustom1 == "23a1a813edce95854cbcafc76b395cd452f057fd25d62dbec061f68541f9e346d539ee1e9c4720ebdb5a3b46fca2e30cbd2788da93d3d29a27e35585f03760d1"))
    print("Is Custom2 correct: " + str(checkCustom2 == "28eb8ec120b9f9fe2be8e015ad952035483b496ef476ee3004952674bb40903a0c40d55d537b10b08be9c6ea3cf08c0d8c80857cd7ae89cb67cd67e685426947"))
    print("Is Custom3 correct: " + str(checkCustom3 == "c0cae648acfdec9218e1705a5f5ada4618a1cb2d68991e4725687a74e5fd5a38a155c95a50f2bf475774be0154c3def737d8e17cffc5e3132ea837f655cc2533"))
    return

# Gets a valid file name as input from the user
def get_input_file(message: str):
    while True:
        try:
            print(message)
            sel = input()
            if os.path.exists(sel):
                return sel
            else:
                print("Invalid selection, file {sel} does not exist.\n".format(sel=sel))
        except ValueError:
            print("Invalid selection, file {sel} does not exist.\n".format(sel=sel))

# Gets a valid input option as input from the user
def get_input_option(message: str, error: str, options: list[str]):
    while True:
        try:
            print(message)
            sel = input()
            if sel in options:
                return sel
            else:
                print("Invalid selection, must be {error}.\n".format(error=error))
        except ValueError:
            print("Invalid selection, must be {error}.\n".format(error=error))

# Gets a valid number as input from the user
def get_input_number(message: str, error: str):
    while True:
        try:
            print(message)
            sel = int(input())
            return sel
        except ValueError:
            print("Invalid selection, must be {error}.\n".format(error=error))

# Hashes the given input 100 times in MD5, 100 times in SHA-256, and 100 times in SHA-512. Returns bytes.
def custom_hash(input, print_steps = True):
    # UTF-8 encode the input if it is not already encoded
    result = byte_encode(input) if not isinstance(input, bytes) else input
    if print_steps:
        print("Hashing {result}".format(result=result.hex()))
    for i in range(NUM_MD5):
        result = md5(result)
        if print_steps:
            print("[MD5-{i}]: {result}".format(i=i, result=result.hex()))
    for i in range(NUM_SHA256):
        result = sha256(result)
        if print_steps:
            print("[SHA256-{i}]: {result}".format(i=i, result=result.hex()))
    for i in range(NUM_SHA512):
        result = sha512(result)
        if print_steps:
            print("[SHA512-{i}]: {result}".format(i=i, result=result.hex()))
    return result

# Hashes the given input in MD5. Returns bytes.
def md5(input):
    # UTF-8 encode the input if it is not already encoded
    if not isinstance(input, bytes):
        input = byte_encode(input)
    digest = list(MD5_INIT)
    size = MD5_W // 8
    message = pad(input, 2 * MD5_W, 'little')

    # Process the message in successive 512-bit chunks:
    for chunk_index in range(0, len(message), MD5_W * 2):
        cur_chunk = message[chunk_index:(chunk_index + MD5_W * 2)]

        # break chunk into sixteen 32-bit words M[j], j < 16
        M = [0] * 16
        M[0:16] = [int.from_bytes(cur_chunk[i:(i+size)], 'little') for i in range(0, len(cur_chunk), size)]

        # Initialize hash value for this chunk:
        h = list(digest)

        # Main loop:
        for i in range(MD5_RUNS):
            if i < 16:
                F = (h[1] & h[2]) | ((~h[1]) & h[3])
                g = i
            elif i < 32:
                F = (h[3] & h[1]) | ((~h[3]) & h[2])
                g = (5*i + 1) % 16
            elif i < 48:
                F = h[1] ^ h[2] ^ h[3]
                g = (3*i + 5) % 16
            else:
                F = h[2] ^ (h[1] | (~h[3]))
                g = (7*i) % 16

            F += h[0] + MD5_K[i] + M[g]
            h[0] = h[3]
            h[3] = h[2]
            h[2] = h[1]
            h[1] = (h[1] + rotl(F, MD5_S[i], MD5_W, MD5_FF)) & MD5_FF
        # Add this chunk's hash to result so far:
        for j in range(len(h)):
            digest[j] = (digest[j] + h[j]) & MD5_FF

    result = b''.join(Di.to_bytes(size, 'little') for Di in digest)
    return result

# Hashes the given input in SHA-256. Returns bytes.
def sha256(input):
    return sha2(input, SHA256_H, SHA256_K, SHA256_SIGMAS, SHA256_RUNS, SHA256_W, SHA256_FF)

# Hashes the given input in SHA-512. Returns bytes.
def sha512(input):
    return sha2(input, SHA512_H, SHA512_K, SHA512_SIGMAS, SHA512_RUNS, SHA512_W, SHA512_FF)

# Hashes the given input of max size 512 bits using SHA-2 (SHA-256/SHA-512)
def sha2(input, SHA_H: list[int], SHA_K: list[int], SHA_SIGMA: dict[str, list[int]], SHA_RUNS: int, SHA_W: int, SHA_FF: int):
    # UTF-8 encode the input if it is not already encoded
    if not isinstance(input, bytes):
        input = byte_encode(input)
    message = pad(input, 2 * SHA_W)
    size = SHA_W // 8
    digest = list(SHA_H)

    # Iterate over message in 512-bit/1024-bit (64/128 byte) chunks
    for chunk_index in range(0, len(message), SHA_W * 2):
        cur_chunk = message[chunk_index:(chunk_index + SHA_W * 2)]

        # Copy chunk into message schedule array w
        w = [0] * SHA_RUNS
        w[0:16] = [int.from_bytes(cur_chunk[i:(i+size)], 'big') for i in range(0, len(cur_chunk), size)]

        # Extend the first 16 words into the remaining 48/64 words w[16..63/79] of the message schedule array:
        for i in range(16, SHA_RUNS):
            sigma0 = ssigma(w[i - 15], SHA_SIGMA["s0"][0], SHA_SIGMA["s0"][1], SHA_SIGMA["s0"][2], SHA_W, SHA_FF)
            sigma1 = ssigma(w[i - 2], SHA_SIGMA["s1"][0], SHA_SIGMA["s1"][1], SHA_SIGMA["s1"][2], SHA_W, SHA_FF)
            w[i] = (w[i - 16] + sigma0 + w[i - 7] + sigma1) & SHA_FF
        
        # Initialize working variables to current hash value:
        h = list(digest)

        # Compression function main loop:
        for i in range(SHA_RUNS):
            sum0 = bsigma(h[0], SHA_SIGMA["b0"][0], SHA_SIGMA["b0"][1], SHA_SIGMA["b0"][2], SHA_W, SHA_FF)
            sum1 = bsigma(h[4], SHA_SIGMA["b1"][0], SHA_SIGMA["b1"][1], SHA_SIGMA["b1"][2], SHA_W, SHA_FF)
            temp1 = h[7] + sum1 + ch(h[4], h[5], h[6]) + SHA_K[i] + w[i]
            temp2 = sum0 + maj(h[0], h[1], h[2])

            h[7] = h[6]
            h[6] = h[5]
            h[5] = h[4]
            h[4] = (h[3] + temp1) & SHA_FF
            h[3] = h[2]
            h[2] = h[1]
            h[1] = h[0]
            h[0] = (temp1 + temp2) & SHA_FF
            
        # Add the compressed chunk to the current hash value:
        for j in range(len(h)):
            digest[j] = (digest[j] + h[j]) & SHA_FF

    result = b''.join(Di.to_bytes(size, 'big') for Di in digest)
    return result

# SHA Helper functions
# Pads the message with a 1, followed by 0s, and then the length of the message
def pad(message: bytes, BITS: int, endian='big'):
    size = BITS // 8
    mdi = len(message) % BITS
    L = (len(message) << 3).to_bytes(size, endian)
    padlen = BITS - size - mdi - 1
    if mdi >= BITS - size:
        padlen += BITS
    
    padded = bytearray(message)
    padded.extend(b'\x80')
    for i in range(padlen):
        padded.extend(b'\x00')
    padded.extend(L)
    return bytes(padded)

# Returns the s-sigma component of SHA-2 (specified in RFC-4634)
def ssigma(word: int, x: int, y: int, z: int, word_len: int, ff: int):
    return rotr(word, x, word_len, ff) ^ rotr(word, y, word_len, ff) ^ (word >> z)

# Returns the b-sigma component of SHA-2 (specified in RFC-4634)
def bsigma(word: int, x: int, y: int, z: int, word_len: int, ff: int):
    return rotr(word, x, word_len, ff) ^ rotr(word, y, word_len, ff) ^ rotr(word, z, word_len, ff)

# Returns the ch component of SHA-2 (specified in RFC-4634)
def ch(x: int, y: int, z: int):
    return (x & y) ^ ((~x) & z)

# Returns the maj component of SHA-2 (specified in RFC-4634)
def maj(x: int, y: int, z: int):
    return (x & y) ^ (x & z) ^ (y & z)

# Rotates the bits of the word right
def rotr(word: int, shift: int, word_len: int, flag: int):
    return ((word >> shift) | (word << (word_len - shift))) & flag

# Rotates the bits of the word left
def rotl(word: int, shift: int, word_len: int, flag: int):
    word &= flag
    return ((word << shift) | (word >> (word_len - shift))) & flag

# Encodes the given string as UTF-8 bytes
def byte_encode(input: str):
    return input.encode('utf-8')

# Main entry point
if __name__ == '__main__':
    sys.exit(main())