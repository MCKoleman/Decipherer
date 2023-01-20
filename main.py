import sys

# Letter frequency, A-Z
LETTER_FREQ = [8.12, 1.49, 2.71, 4.32, 12.02, 2.30, 2.03, 
    5.92, 7.31, 0.10, 0.69, 3.98, 2.61, 6.95, 7.68, 1.82, 
    0.11, 6.02, 6.28, 9.10, 2.88, 1.11, 2.09, 0.17, 2.11, 0.07]
A_UPPER = 65
Z_UPPER = 90
A_LOWER = 97
Z_LOWER = 122
LETTER_COUNT = 26

# A program that can encipher any given text or try to decipher ciphered text
def main():
    print("Select mode:")
    print("[1] Encipher")
    print("[2] Decipher")
    mode = input()

    match mode:
        case "1":
            encipher()
        case "2":
            decipher()
        case _:
            print("Invalid selection")
    return

# Logic for the enciphering menu
def encipher():
    text = input("Enter text to encipher: ")
    print("Select cipher to use:")
    print("[1] Caesar")
    cipher = input()

    match cipher:
        case "1":
            key = input("Select key [1-26]: ")
            print("Enciphered text: " + caesar(text, int(key)))
        case _:
            print("Invalid selection, exiting.")
    return

# Logic for the deciphering menu
def decipher():
    text = input("Enter text to decipher: ")
    print("Select cipher to try:")
    print("[1] Caesar")
    print("[2] Simple Substitution")
    cipher = input()

    match cipher:
        case "1":
            key = test_caesar(text)
            print("Key selected: " + key)
            print("Deciphered text: " + caesar(text, int(key)))
        case "2":
            key = test_substitution(text)
            print("Key selected: " + key)
            print("Deciphered text: " + substitution(text, int(key)))
        case _:
            print("Invalid selection, exiting.")
    return

# Tests all possible caesar ciphers on the given text
def test_caesar(text):
    mode = input("Mode: [1] Force, [2] Guess: ")
    if mode == "1":
        for i in range(0, 26):
            print("[{key}]: ".format(key=i), end='')
            print(caesar(text, i))

        key = input("Select key that matches [1-26]: ")
    elif mode == "2":
        freq = get_letter_freq(text)
        max_cipher = freq.index(max(freq))
        max_real = LETTER_FREQ.index(max(LETTER_FREQ))
        key = max_real - max_cipher
        if key < 0:
            key += LETTER_COUNT

        print("[{key}]: ".format(key=key), end='')
        print(caesar(text, key))
    else:
        key = 0
    return str(key)

# Applies the caesar cipher of the given key to the given text.
def caesar(text, key):
    result = ""
    for letter in text:
        result += shift_letter(letter, key)
    return result

def test_substitution(text):
    return

def substitution(text, key):
    return

# Counts the number of occurences of each letter in a text
def get_letter_freq(text):
    list = [0] * 26
    for letter in text:
        index = letter_to_index(letter)
        if index >= 0:
            list[index] += 1
    return list

# Shifts the given letter by the given shift. Does not affect non-letters.
def shift_letter(letter, shift):
    if is_upper(letter):
        return chr((((letter_to_index(letter) + shift) % LETTER_COUNT) + A_UPPER))
    elif is_lower(letter):
        return chr((((letter_to_index(letter) + shift) % LETTER_COUNT) + A_LOWER))
    else:
        return letter

# Converts a letter to that letter's index in the alphabet [0-25]. Returns -1 if not a letter.
def letter_to_index(letter):
    if is_upper(letter):
        return ord(letter) - A_UPPER
    elif is_lower(letter):
        return ord(letter) - A_LOWER
    else:
        return -1

# Returns whether the letter is a lowercase letter
def is_lower(letter):
    return ord(letter) >= A_LOWER and ord(letter) <= Z_LOWER

# Returns whether the letter is an uppercase letter
def is_upper(letter):
    return ord(letter) >= A_UPPER and ord(letter) <= Z_UPPER

if __name__ == '__main__':
    sys.exit(main())
