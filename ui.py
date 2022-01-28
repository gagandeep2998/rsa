from tkinter import *
from tkinter import messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from tkinter.filedialog import askopenfilename


class Auth:
    def __init__(self):
        self.is_auth = False
        self.window = Tk()
        self.window.title("Login")
        self.window.config(padx=20, pady=20)

        self.canvas = Canvas(width=200, height=200)
        self.logo_img = PhotoImage(file='images/logo.png')
        self.canvas.create_image(100, 100, image=self.logo_img)
        self.canvas.grid(column=1, row=0)

        self.username_label = Label(text='Username: ')
        self.username_label.grid(column=0, row=1, padx=10, pady=10)

        self.username_entry = Entry(width=35)
        self.username_entry.grid(column=1, row=1, padx=10, pady=10)
        self.username_entry.focus()

        self.password_label = Label(text='Password: ')
        self.password_label.grid(column=0, row=2, padx=10, pady=10, sticky='EW')

        self.pass_entry = Entry(width=35, show='*')
        self.pass_entry.grid(column=1, row=2, padx=10, pady=10, sticky='EW')

        self.login_button = Button(text='Login', command=self.authentication)
        self.login_button.grid(column=1, row=3, padx=10, pady=10)
        self.window.mainloop()

    def authentication(self):
        username = self.username_entry.get()
        password = self.pass_entry.get()
        if username == 'admin' and password == 'password':
            messagebox.showinfo(title='Success', message='Welcome Admin!')
            self.is_auth = True
            self.window.destroy()
        else:
            messagebox.showinfo(title='Error', message='Wrong username or password!')
            self.username_entry.delete(0, END)
            self.pass_entry.delete(0, END)
            self.username_entry.focus()


class Rsa:
    def __init__(self):
        self.want_enc = False
        self.want_dec = False
        self.window = Tk()
        self.window.title("RSA Encryption")
        self.window.config(padx=20, pady=20)

        self.canvas = Canvas(height=189, width=336, highlightthickness=0)
        self.banner_img = PhotoImage(file='images/banner.png')
        self.canvas.create_image(168, 95, image=self.banner_img)
        self.canvas.grid(column=0, row=0, columnspan=2, padx=20, pady=20)

        self.enc_button_img = PhotoImage(file='images/enc_button.png')
        self.enc_button = Button(image=self.enc_button_img, command=self.enc)
        self.enc_button.grid(column=0, row=1, padx=20, pady=20)

        self.dec_button_img = PhotoImage(file='images/dec_img.png')
        self.dec_button = Button(image=self.dec_button_img, command=self.dec)
        self.dec_button.grid(column=1, row=1, padx=20, pady=20)

        self.window.mainloop()

    def enc(self):
        self.want_enc = True
        self.window.destroy()

    def dec(self):
        self.want_dec = True
        self.window.destroy()


class Encrypt:
    def __init__(self):
        self.window = Tk()
        self.window.title("Encryption")
        self.window.config(padx=20, pady=20)

        self.canvas = Canvas(height=200, width=200, highlightthickness=0)
        self.enc_img = PhotoImage(file='images/enc.png')
        self.canvas.create_image(100, 100, image=self.enc_img)
        self.canvas.grid(column=1, row=1)

        self.message_label = Label(text='Message: ')
        self.message_label.grid(column=0, row=2, padx=10, pady=10)

        self.message_entry = Entry(width=100)
        self.message_entry.grid(column=1, row=2, padx=10, pady=10)
        self.message_entry.focus()

        self.public_key_label = Label(text='Public Key: ')
        self.public_key_label.grid(column=0, row=3, padx=10, pady=10)

        self.public_key_path_label = Label(text='Saved as public_key.pem')
        self.public_key_path_label.grid(column=1, row=3, padx=10, pady=10)

        self.private_key_label = Label(text='Private Key: ')
        self.private_key_label.grid(column=0, row=4, padx=10, pady=10)

        self.private_key_path_label = Label(text='Saved as private_key.pem')
        self.private_key_path_label.grid(column=1, row=4, padx=10, pady=10)

        self.enc_txt_label = Label(text='Encrypted Text: ')
        self.enc_txt_label.grid(column=0, row=5, padx=10, pady=10)

        self.enc_entry = Entry(width=100)
        self.enc_entry.grid(column=1, row=5, padx=10, pady=10)

        self.enc_button = Button(text='Encrypt', command=self.encryption)
        self.enc_button.grid(column=1, row=6, padx=10, pady=10)

        self.window.mainloop()

    def encryption(self):
        key_pair = RSA.generate(1024)
        pub_key = key_pair.publickey()
        pub_key_pem = pub_key.exportKey()
        priv_key_pem = key_pair.exportKey()

        with open('key_pairs.pem', mode='wb') as key_file:
            key_file.write(key_pair.export_key("PEM"))

        with open('public_key.pem', mode='wb') as public_key:
            public_key.write(pub_key_pem)

        with open('private_key.pem', mode='wb') as private_key:
            private_key.write(priv_key_pem)

        message = self.message_entry.get()
        encryptor = PKCS1_OAEP.new(pub_key)
        encrypted = encryptor.encrypt(bytes(message, encoding='utf8'))
        self.enc_entry.insert(0, str(encrypted))

        with open('enc_text.txt', mode='wb') as enc_text:
            enc_text.write(encrypted)
            messagebox.showinfo(title='Success', message="Encrypted Message written in enc_text.txt")
            self.message_entry.delete(0, END)
            self.enc_entry.delete(0, END)


class Decrypt:
    def __init__(self):
        self.key_file_path = None
        self.enc_file_path = None

        self.window = Tk()
        self.window.title('Decryption')
        self.window.config(padx=20, pady=20)

        self.canvas = Canvas(height=200, width=200, highlightthickness=0)
        self.dec_img = PhotoImage(file='images/dec.png')
        self.canvas.create_image(100, 100, image=self.dec_img)
        self.canvas.grid(column=1, row=0)

        self.key_select_label = Label(text='Select the key_pairs.pem file: ')
        self.key_select_label.grid(column=0, row=1, padx=20, pady=20)

        self.select_key_button = Button(text='Select key', command=self.select_key)
        self.select_key_button.grid(column=1, row=1, padx=20, pady=20)

        self.key_file_path_label = Label(text='No file selected')
        self.key_file_path_label.grid(column=2, row=1)

        self.enc_select_label = Label(text='Select the enc_text.txt file: ')
        self.enc_select_label.grid(column=0, row=2, padx=20, pady=20)

        self.enc_select_button = Button(text="Select Encrypted File", command=self.select_enc_file)
        self.enc_select_button.grid(column=1, row=2, padx=20, pady=20)

        self.enc_file_path_label = Label(text='No file selected')
        self.enc_file_path_label.grid(column=2, row=2)

        self.dec_txt_label = Label(text='Decrypted Text: ')
        self.dec_txt_label.grid(column=0, row=3, padx=20, pady=20)

        self.dec_txt_entry = Entry(width=100)
        self.dec_txt_entry.grid(column=1, row=3, padx=20, pady=20)

        self.dec_button = Button(text='Decrypt Text', command=self.decrypt_txt)
        self.dec_button.grid(column=1, row=4, padx=20, pady=20)

        self.window.mainloop()

    def select_key(self):
        self.key_file_path = askopenfilename()
        self.key_file_path_label.config(text=self.key_file_path)

    def select_enc_file(self):
        self.enc_file_path = askopenfilename()
        self.enc_file_path_label.config(text=self.enc_file_path)

    def decrypt_txt(self):
        if 'key_pairs.pem' not in self.key_file_path:
            messagebox.showinfo(title="Error", message='Please select correct key file!')
        else:
            with open(self.key_file_path, mode='rb') as key_pairs:
                key_pair = RSA.import_key(key_pairs.read())
                # print(key_pair)

        if 'enc_text.txt' not in self.enc_file_path:
            messagebox.showinfo(title="Error", message="Please select correct encrypted file!")
        else:
            with open(self.enc_file_path, mode='rb') as enc_text_file:
                enc_text = enc_text_file.read()
                # print(enc_text)

            decrypter = PKCS1_OAEP.new(key_pair)
            decrypted_text = decrypter.decrypt(enc_text)
            self.dec_txt_entry.insert(0, str(decrypted_text))
