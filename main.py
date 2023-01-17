import sys

def main():
    text = input("Enter text to decipher: ")
    print("Select cipher to try:")
    print("[1] Caesar")
    cipher = input()

    match cipher:
        case "1":
            key = test_caesar(text)
            print("Key selected: " + key)
            print("Deciphered text: " + caesar(text, int(key)))
        case _:
            print("Invalid selection, exiting.")
    return

def test_caesar(text):
    for i in range(0, 26):
        print("[{key}]: ".format(key=i), end='')
        print(caesar(text, i))

    key = input("Select key that matches [1-26]: ")
    return key

def caesar(text, key):
    result = ""
    for letter in text:
        if ord(letter) >= 65 and ord(letter) <= 90:
            result += chr((((ord(letter) - 65 + key) % 26) + 65))
        elif ord(letter) >= 97 and ord(letter) <= 122:
            result += chr((((ord(letter) - 97 + key) % 26) + 97))
        else:
            result += letter
    return result

if __name__ == '__main__':
    sys.exit(main())
