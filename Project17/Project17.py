func (box *Box) encrypt(pw *Password) error {
    block, err := aes.NewCipher([]byte(md5sum(box.masterPassword)))
    if err != nil {
        return err
    }
    if len(pw.AccountIV) != block.BlockSize() {
        pw.AccountIV = make([]byte, block.BlockSize())
        // crand aliases crypto/rand
        if _, err := crand.Read(pw.AccountIV); err != nil {
            return err
        }
    }
    if len(pw.PasswordIV) != block.BlockSize() {
        pw.PasswordIV = make([]byte, block.BlockSize())
        if _, err := crand.Read(pw.PasswordIV); err != nil {
            return err
        }
    }
    pw.CipherAccount = cfbEncrypt(block, pw.AccountIV, []byte(pw.PlainAccount))
    pw.CipherPassword = cfbEncrypt(block, pw.PasswordIV, []byte(pw.PlainPassword))
    return nil
}

func cfbEncrypt(block cipher.Block, iv, src []byte) []byte {
    cfb := cipher.NewCFBEncrypter(block, iv)
    dst := make([]byte, len(src))
    cfb.XORKeyStream(dst, src)
    return dst
}
