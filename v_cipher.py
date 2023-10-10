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
NUM_RESULTS = 2
ENG_IOC = 0.065

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
    key = input("Enter keyword: ")
    print("Enciphered text: " + vigenere(text, key))
    return

# Logic for the deciphering menu
def decipher():
    text = input("Enter text to decipher: ")
    key = test_vigenere(text)
    print("Keyword: [{key}]".format(key=key))
    print("Deciphered text: " + vigenere(text, key))
    return

# Tests possible vigenere ciphers on the given text
def test_vigenere(text: str):
    key = ""
    key_size = guess_key_length(text)
    for key_index in range(key_size):
        key += index_to_letter(frequency_analysis(get_split_text(text, key_index, key_size), NUM_RESULTS))
    print("Likely key length: [{key_size}]".format(key_size=key_size))
    return str(key)

# Applies the vigenere cipher of the given key to the given text
def vigenere(text: str, key: str):
    result = ""
    v_index = 0
    for letter in text:
        result += shift_letter(letter, letter_to_index(key[v_index]))

        # Only shift index after letters
        if is_upper(letter) or is_lower(letter):
            v_index = (v_index + 1) % len(key)
    return result

# Counts the number of occurences of each letter in a text
def get_letter_count(text: str):
    list = [0] * LETTER_COUNT
    for letter in text:
        index = letter_to_index(letter)
        if index >= 0:
            list[index] += 1
    return list

# Gets the relative frequency of occurences of each letter in a text
def get_letter_freq(text: str):
    list = [0.0] * LETTER_COUNT
    num_chars = 0.0
    for letter in text:
        index = letter_to_index(letter)
        if index >= 0:
            list[index] += 1.0
            num_chars += 1.0
    for i in range(len(list)):
        if list[i] > 0.0:
            list[i] = round(list[i] / num_chars, 3)
    return list

# Returns the index of coincidence of the given text
def index_of_coincidence(text: str):
    list = get_letter_count(text)
    num_letters = 0
    sum = 0.0
    for elem in list:
        if elem > 0:
            sum += elem*(elem - 1)
            num_letters += 1
    #print("Sum: " + str(sum) + ", NumLetters: " + str(num_letters))
    return sum / (num_letters * (num_letters - 1))

# Performs frequency analysis on the given text, returning the best caesar cipher shift guess
def frequency_analysis(text: str, num_results: int):
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

# Guesses the key length [1-4] using the IOCs of different divisions
def guess_key_length(text: str):
    best_key_size = 0
    best_ioc_sum = 0.0
    for key_size in range(1, 5):
        ioc_sum = 0.0
        for offset in range(0, key_size):
            #print(get_split_text(text, offset, key_size))
            #print(index_of_coincidence(get_split_text(text, offset, key_size)))
            ioc_sum += abs(ENG_IOC - index_of_coincidence(get_split_text(text, offset, key_size)))
        ioc_sum = ioc_sum
        #print("[{key_size}]: {ioc_sum}".format(key_size=key_size, ioc_sum=ioc_sum))
        if ioc_sum > best_ioc_sum:
            best_ioc_sum = ioc_sum
            best_key_size = key_size
    return best_key_size

# Splits the text returning letters from the text at every split with given offset
def get_split_text(text: str, offset: int, split: int):
    if split <= 1:
        return text

    result = ""
    clean_text = get_clean_text(text)
    for i in range(len(clean_text)):
        if (i + offset) % split == 0:
            result += clean_text[i]
    return result

# Returns the cleaned up text with only letters
def get_clean_text(text: str):
    result = ""
    for letter in text:
        if is_lower(letter) or is_upper(letter):
            result += letter
    return result

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

# Returns the index [0-25] as an ASCII letter
def index_to_letter(index: int):
    return chr(index + A_UPPER)

# Returns whether the letter is a lowercase letter
def is_lower(letter: str):
    return ord(letter) >= A_LOWER and ord(letter) <= Z_LOWER

# Returns whether the letter is an uppercase letter
def is_upper(letter: str):
    return ord(letter) >= A_UPPER and ord(letter) <= Z_UPPER

if __name__ == '__main__':
    sys.exit(main())
