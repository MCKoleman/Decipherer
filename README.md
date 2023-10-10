# Decipherer
This project implements various encryption methods and provides crude tools to attempt to decode those same
encryption methods. I made this project to learn how different encrypytion methods work and to implement
the pseudocode of the encryption algorithms for them so that I could get a better grasp of cryptography.  

Three different programs are included for encoding and decoding text.  
[c_cipher](/c_cipher.py) encodes or decodes text with the Caesar Cipher  
[v_cipher](/v_cipher.py) encodes or decodes text with the Vigenere Cipher  
[Decoder](/decoder.py) encodes or attempts to decode text with the MD5, SHA-256, or SHA-512 algorithms  

# Caesar Cipher
### Code description
The c_cipher program allows for encrypting or decrypting of any caesar/shift cipher text. The program allows the user to first select either encryption or decryption mode.  

In encryption mode, the user can type any plaintext and then give a numerical key in the range of 1-26, enciphering the given text using that key. The key is always assumed to be to the right. Entering any invalid input closes the program.  

In decryption mode, the user can type any ciphertext and then choose between two modes of decryption: brute force and frequency analysis. The code then returns both the deciphered text and the key (right and left keys) for the shift cipher regardless of the mode of decryption.  
The code can be compiled using a bash/unix terminal and running `make -B -f Makefile c_cipher`. This results in an executable `c_cipher`, which can be run using the command `./c_cipher` in a terminal.  

### Attack method
The program implements both frequency analysis and brute force deciphering. Frequency analysis returns the most likely result with high accuracy, with the accuracy of the guess higher the longer the text is, while brute force returns all possible results, relying on a human to find the correct deciphering from the list. Frequency analysis fails for short texts like single words, where finding patterns is difficult, and brute force becomes the best option. For longer texts, reading the list of brute force results may be cumbersome, but the frequency analysis results are much more reliable.  

In brute force mode, all 26 possible plaintexts are displayed, and the user can choose one to get the key.  

In frequency analysis mode, the program analyses the frequency of each letter in the ciphertext to the frequency of letters in standard English text. The program then analyses which shift between 0 and 25 makes the frequency of the letters in the ciphertext match closest to the frequency of letters in English, and returns both the key and deciphered text. If frequency analysis does not produce a sensible result, brute force can always be used as a backup method.

# Vigenere Cipher
### Code description
The v_cipher program allows for encrypting or decrypting of any Vigenère cipher text. The program allows the user to first select either encryption or decryption mode.  

In encryption mode, the user can type any plaintext and then give a keyword, enciphering the given text using a Vigenère cipher with that key. The key for enciphering can have any positive length.  

In decryption mode, the user can type any ciphertext created using a key of length 4 or less, which is then deciphered using frequency analysis. The code then returns both the deciphered text and the keyword for the Vigenère cipher. The code only returns the most likely keyword, resulting in high error for short samples such as single sentences.  

The code can be compiled using a bash/unix terminal and running `make -B -f Makefile v_cipher`. This results in an executable `v_cipher`, which can be run using the command `./v_cipher` in a terminal.  

### Attack method
The code uses index of coincidence estimations to first guess the length of the key (1-4) for the cipher. Then the code runs frequency analysis individually for each grouping of letters displaced by the length of the key (i.e. analyzing letters 0, 4, 8, …, n and 1, 5, 9, …, n+1 etc. as a group for a key length of 4). After analyzing each of the groups of letters, the program combines the best guesses for each of the groups into one keyword, and then returns the plaintext using that keyword.  


# Decoder
### Code description
The decoder program allows for encrypting or decrypting of text with the MD5, SHA-256, SHA-512 algorithms or with a custom encryption algorithm that uses MD5, SHA-256, and SHA-512 100 times each. The program allows the user to first select either encryption or decryption mode and then the type of algorithm they want to use.  

In encryption mode, the user can type any plaintext, enciphering the given text using the chosen encryption algorithm.  

In decryption mode, the user can type any ciphertext and choose either wordlist or bruteforce decryption mode.  

In bruteforce mode, the user can also choose which character spaces to include, choosing from any combination of upper and lowercase letters, numbers, and special characters. It then attempts every combination of characters in the character space for all possible lengths, starting from the minimum length given and ending at the maximum length, returning the original word if it is recovered.  

In wordlist mode, the program runs through every word in the provided wordlist, enciphering them in the chosen algorithm and checking for a match against the provided text, returning the original word on a success.  

The code can be compiled using a bash/unix terminal and running `make -B -f Makefile decoder`. This results in an executable `decoder`, which can be run using the command `./decoder` in a terminal.  

### Attack method
The code implements both a wordlist based attack and a bruteforce attack. In wordlist mode, the program evaluates all given words that can be filtered manually beforehand to increase the speed of the attack. In bruteforce mode, the program evaluates all possible combinations of all the characters in the chosen character space, which can be narrowed down by evaluating the possible characters in the word, e.g. by checking the password requirements of a website and not including special characters in the run for a password from a website that does not use special characters. The speed of the bruteforce method can only be improved by providing more computation power, decreasing the length of the guess, or reducing the character space.  