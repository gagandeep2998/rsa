from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

enc = bytes()
from tkinter import *
'''this is the root window '''
global  text1

def auth():
    root = Tk()
    def myClick():
        if userName.get() == 'admin' and password.get() == 'password':
            mylabel1 = Label(root, text="Welcome Admin!")
            mylabel1.grid(row=4, column=1)
            
            def rsa1():
                root = Tk()
                mylabel1 = Label(root, text = "Message")
                message = Entry(root, width=50)
                mylabel1.grid(row=0, column=0)
                message.grid(row=0, column=1)
                
                keyPair = RSA.generate(1024)
                pubKey = keyPair.publickey()
                pubKeyPEM = pubKey.exportKey()
                privKeyPEM = keyPair.exportKey()
                
                
                def encr():
                        global encrypted
                        text1 = message.get()
                        encryptor = PKCS1_OAEP.new(pubKey)
                        encrypted = encryptor.encrypt(bytes(text1, encoding='utf8')) #bytes(text1, encoding='utf8')
                        encrpytedMessage.insert(0, str(encrypted))
                        #print(encrypted)
                def decr():
                        decryptor = PKCS1_OAEP.new(keyPair)
                        decrypttext = decryptor.decrypt(encrypted)
                        decrypted.insert(0, decrypttext)
                        
                
                encrypt = Button(root, text = "Encrypt", padx=5,pady=5,command=encr)
                mylabel2 = Label(root, text = "PublicKey")
                publicKey = Entry(root, width=100)
                publicKey.insert(0, str(pubKeyPEM))
                mylabel3 = Label(root, text = "PrivateKey")
                privateKey = Entry(root, width = 100)
                privateKey.insert(0, str(privKeyPEM))
                mylabel4 = Label(root, text = "Encrypted Message")
                encrpytedMessage = Entry(root,width=50)
                
                
                encrypt.grid(row=1, column=1)
                mylabel2.grid(row=2, column=0)

                publicKey.grid(row=2, column=1)
                mylabel3.grid(row=4, column=0)
                privateKey.grid(row=4, column=1)
                mylabel4.grid(row=5, column=0)
                encrpytedMessage.grid(row=5, column=1)

                decrypt = Button(root, text="Decrypt", padx=5, pady=5, command=decr)
                mylabel15 = Label(root, text = "Decrypted Text")
                decrypted = Entry(root, width=50)

                decrypt.grid(row=6, column=1)
                mylabel15.grid(row=7, column=0)
                decrypted.grid(row=7, column=1)
                
			

                
                
                
            
            rsa1()
        else:
            mylabel1 = Label(root, text="Wrong username or password")
            mylabel1.grid(row=4, column=1)

    '''label widget'''

    myLabel1 = Label(root, text="UserName")
    userName = Entry(root)
    myLabel2 = Label(root, text="Password")
    password = Entry(root,show="*")

    '''showing the label on to the screen'''
    myLabel1.grid(row=0, column=0)
    userName.grid(row=0, column=1)
    myLabel2.grid(row=1, column=0)
    password.grid(row=1, column=1)
    myButton = Button(root, text = "Sign in", padx=5,pady=5, command=myClick)
    myButton.grid(row = 2, column = 1)
    root.mainloop()

auth()


