from ui import Auth, Encrypt, Rsa, Decrypt

auth = Auth()

if auth.is_auth:
    rsa = Rsa()
    if rsa.want_enc:
        encrypt = Encrypt()
    elif rsa.want_dec:
        decrypt = Decrypt()


