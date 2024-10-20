import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from base64 import b64encode, b64decode
import cv2
import wave

class AESCipher(object):
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, plain_text):
        plain_text = plain_text.encode('utf-8')
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(pad(plain_text, AES.block_size))
        return b64encode(iv + encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = unpad(cipher.decrypt(encrypted_text[self.block_size:]), AES.block_size)
        return plain_text.decode('utf-8')

def ascii_to_binary(input_string):
    binary_list = [format(ord(char), '08b') for char in input_string]
    binary_string = ''.join(binary_list)
    return binary_string

def binary_to_ascii(binary_string):
    chunks = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    ascii_string = ''.join(chr(int(chunk, 2)) for chunk in chunks)
    return ascii_string

def encode_img(img,cipher_text):
    new_file_name = input("Enter the name of the new file without Extension : ")
    length_data = len(cipher_text)
    index_data = 0
    for i in img:
        for pixel in i:
            r, g, b = [f"{channel:08b}" for channel in pixel]
            if index_data < length_data:
                pixel[0] = int(r[:-1] + cipher_text[index_data], 2) 
                index_data += 1
            if index_data < length_data:
                pixel[1] = int(g[:-1] + cipher_text[index_data], 2) 
                index_data += 1
            if index_data < length_data:
                pixel[2] = int(b[:-1] + cipher_text[index_data], 2) 
                index_data += 1
            if index_data >= length_data:
                break
    cv2.imwrite(f"{new_file_name}.png", img)
def decode_img(image):
    img = cv2.imread(image)
    datalen = 32
    f = False
    bin_retrieve = ''
    cipher_len = 0
    cipher_text = ''
    for row in img:
        for pixel in row:
            r, g, b = [f"{channel:08b}" for channel in pixel]
            for channel in (r, g, b):
                if datalen > 0:
                    bin_retrieve += channel[-1]
                    datalen -= 1
                elif datalen == 0:
                    datalen = -1
                    f = True
                    cipher_len = int(bin_retrieve, 2)

                if f and cipher_len > 0:
                    cipher_text += channel[-1]
                    cipher_len -= 1

            if cipher_len <= 0 and f:
                return cipher_text

def decrypt_img():
    img = input("Enter the name of the image you want to decrypt : ")
    key = input("Enter the key : ")
    cipher_text = decode_img(img)
    cipher_ascii = binary_to_ascii(cipher_text)
    try:
        decipher = AESCipher(key)
        decrypted_text = decipher.decrypt(cipher_ascii)
        print("The Secret Message is: " + decrypted_text)
    except ValueError as e:
        print("Decryption failed:")

def encrypt_img():
    img_file_name = input("Enter the image filename with Extension : ")
    plain_text = input("Enter the PlainText : ")
    key = input("Enter the Key : ")
    cipher = AESCipher(key)
    cipher_text = cipher.encrypt(plain_text)
    bin_cipher_text = ascii_to_binary(cipher_text)
    len_bin_cipher_text = format(len(bin_cipher_text), '032b')
    combined_cipher = len_bin_cipher_text + bin_cipher_text
    img = cv2.imread(img_file_name)
    height, width, _ = img.shape
    total_pixels = height * width *3
    if(len(combined_cipher)>total_pixels):
        print("Enter a bigger Image")
    else:
        encode_img(img,combined_cipher)
        
def encode_aud(aud,cipher):
    output_file = input("Enter the output filename (.wav) : ")
    with wave.open(aud, mode='rb') as song:
        nframes = song.getnframes()
        frames = song.readframes(nframes)
        frame_list = list(frames)
        frame_bytes = bytearray(frame_list)
        if len(cipher) > len(frame_bytes):
            print("Cipher text is too long for the given audio file.")
            return  

        for i in range(len(cipher)):
            bit = int(cipher[i])
            if bit == 0:
                frame_bytes[i] &= 254  
            else:
                frame_bytes[i] |= 1   
        
        print("Cipher text encoded successfully.")
        with wave.open(output_file, 'wb') as fd:
            fd.setparams(song.getparams())
            fd.writeframes(frame_bytes)

def decrypt_aud(cipher_binary):
    key = input("Enter Key to Decrypt : ")
    cipher_ascii = binary_to_ascii(cipher_binary)
    try:
        decipher = AESCipher(key)
        decrypted_text = decipher.decrypt(cipher_ascii)
        print("The Secret Message is: " + decrypted_text)
    except ValueError as e:
        print("Decryption failed:")
    return
    
def decode_aud():
    aud = input("Enter the audio filename to be decrypted (.wav) : ")
    with wave.open(aud, mode='rb') as song:
        nframes = song.getnframes()
        frames = song.readframes(nframes)
        frame_bytes = bytearray(frames)
        cipher_length = int(''.join(str(byte & 1) for byte in frame_bytes[:32]), 2)
        cipher_binary = ''.join(str(byte & 1) for byte in frame_bytes[32:32+cipher_length])
        decrypt_aud(cipher_binary) 

def encrypt_aud():
    aud_file_name = input("Enter the audio filename (.wav) : ")
    plain_text = input("Enter the PlainText : ")
    key = input("Enter the Key : ")
    cipher = AESCipher(key)
    cipher_text = cipher.encrypt(plain_text)
    bin_cipher_text = ascii_to_binary(cipher_text)
    len_bin_cipher_text = format(len(bin_cipher_text), '032b')
    combined_cipher = len_bin_cipher_text + bin_cipher_text
    encode_aud(aud_file_name,combined_cipher)


def img_steganography():
    while True:
        ch = int(input("Enter 1 to Encrypt |  2 to Decrypt  | 3 to Exit : "))
        if(ch==1):
            encrypt_img()   
        elif ch==2:
            decrypt_img()
        else:
            return
        
def aud_steganography():
    while True:
        ch = int(input("Enter 1 to Encrypt |  2 to Decrypt  | 3 to Exit : "))
        if(ch==1):
            encrypt_aud()   
        elif ch==2:
            decode_aud()
        else:
            return
        
def main():
    while(True):
        ch = int(input("Enter 1 for Image |  2 to Audio  | 3 to Exit : "))
        if(ch==1):
            img_steganography()
        elif ch==2:
            aud_steganography()
        else:
            return
    
if __name__ == "__main__":
    main()

