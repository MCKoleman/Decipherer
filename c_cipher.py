#!/usr/bin/env python

import sys

# Letter frequency, A-Z
LETTER_FREQ = [0.0812, 0.0149, 0.0271, 0.0432, 0.1202, 0.0230, 0.0203, 
    0.0592, 0.0731, 0.0010, 0.0069, 0.0398, 0.0261, 0.0695, 0.0768, 0.0182, 
    0.0011, 0.0602, 0.0628, 0.0910, 0.0288, 0.0111, 0.0209, 0.0017, 0.0211, 0.0007]
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
    key = input("Select key [1-26]: ")
    print("Enciphered text: " + caesar(text, int(key)))
    return

# Logic for the deciphering menu
def decipher():
    text = input("Enter text to decipher: ")
    key = test_caesar(text)
    print("Key selected: [{right_key}R | {left_key}L]".format(right_key=key, left_key=(LETTER_COUNT-int(key))))
    print("Deciphered text: " + caesar(text, int(key)))
    return

# Tests possible caesar ciphers on the given text
def test_caesar(text: str):
    print("Guessing Mode:")
    print("[1] Brute Force")
    print("[2] Frequency Analysis")
    mode = input()

    # Tests all possible caesar ciphers on the given text
    if mode == "1":
        for i in range(0, 26):
            print("[{key}]: ".format(key=i), end='')
            print(caesar(text, i))

        key = input("Select key that matches [0-25]: ")
    # Runs frequency analysis on all caesar ciphers on the given text
    elif mode == "2":
        key = frequency_analysis(text)
        #print("[Frequency Analysis] [{freq_guess}]: ".format(freq_guess=key), end='')
        #print(caesar(text, key))
    else:
        key = 0
    return str(key)

# Applies the caesar cipher of the given key to the given text.
def caesar(text: str, key: int):
    result = ""
    for letter in text:
        result += shift_letter(letter, key)
    return result

# Counts the number of occurences of each letter in a text
def get_letter_freq(text: str):
    list = [0] * LETTER_COUNT
    for letter in text:
        index = letter_to_index(letter)
        if index >= 0:
            list[index] += 1
    for i in range(len(list)):
        list[i] = round(list[i] / len(list), 3)
    return list

# Performs frequency analysis on the given text, returning the best caesar cipher shift guess
def frequency_analysis(text: str):
    letter_freq = get_letter_freq(text)
    best_shift = -1
    best_variance = sys.maxsize
    for shift in range(LETTER_COUNT):
        variance = 0
        for index in range(len(LETTER_FREQ)):
            if(letter_freq[(index - shift) % LETTER_COUNT] > 0.0):
                variance += abs(LETTER_FREQ[index] - letter_freq[(index - shift) % LETTER_COUNT])
        #print("[{shift}] text variance: {variance}".format(shift=shift, variance=variance))
        if variance < best_variance:
            best_variance = variance
            best_shift = shift
    return best_shift

# Shifts the given letter by the given shift. Does not affect non-letters.
def shift_letter(letter: str, shift: int):
    if is_upper(letter):
        return chr((((letter_to_index(letter) + shift) % LETTER_COUNT) + A_UPPER))
    elif is_lower(letter):
        return chr((((letter_to_index(letter) + shift) % LETTER_COUNT) + A_LOWER))
    else:
        return letter

# Converts a letter to that letter's index in the alphabet [0-25]. Returns -1 if not a letter.
def letter_to_index(letter: str):
    if is_upper(letter):
        return ord(letter) - A_UPPER
    elif is_lower(letter):
        return ord(letter) - A_LOWER
    else:
        return -1

# Returns whether the letter is a lowercase letter
def is_lower(letter: str):
    return ord(letter) >= A_LOWER and ord(letter) <= Z_LOWER

# Returns whether the letter is an uppercase letter
def is_upper(letter: str):
    return ord(letter) >= A_UPPER and ord(letter) <= Z_UPPER

if __name__ == '__main__':
    sys.exit(main())
