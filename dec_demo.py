from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from tkinter.filedialog import askopenfilename

key_file_name = askopenfilename()
print(key_file_name)

with open(key_file_name, mode='rb') as key_pairs:
    key_pair = RSA.import_key(key_pairs.read())
    print(key_pair)

with open('enc_text.txt', mode='rb') as enc_text_file:
    enc_text = enc_text_file.read()

decryptor = PKCS1_OAEP.new(key_pair)


decrypttext = decryptor.decrypt(enc_text)
print(decrypttext)