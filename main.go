package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

var (
	initialVector = "1234567890123456"
	passphrase    = "Impassphrasegood"
)

func main() {
	password := "1q2w3e4r5t6y"
	salt := "84758392058473948573847596"

	custID := "1q2w3e4r5t6y7u8i"

	dk := pbkdf2.Key([]byte(password), []byte(salt), 1024, 16, sha1.New)

	fmt.Println("", dk)
	str4 := hex.EncodeToString(dk)
	fmt.Println("", str4)

	fmt.Println(len(str4))

	encryptedData := AESEncrypt(custID, dk)

	// encryptedString := base64.StdEncoding.EncodeToString(encryptedData)
	fmt.Println(hex.EncodeToString(encryptedData))

	// encryptedData, _ = base64.StdEncoding.DecodeString(encryptedString)
	decryptedText := AESDecrypt(encryptedData, dk)
	fmt.Println(string(decryptedText))

}

func AESEncrypt(src string, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("key error1", err)
	}
	if src == "" {
		fmt.Println("plain content empty")
	}
	ecb := cipher.NewCBCEncrypter(block, []byte("1234567890123456"))
	content := []byte(src)
	content = PKCS5Padding(content, block.BlockSize())
	crypted := make([]byte, len(content))
	ecb.CryptBlocks(crypted, content)

	return crypted
}

func AESDecrypt(crypt []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("key error1", err)
	}
	if len(crypt) == 0 {
		fmt.Println("plain content empty")
	}
	ecb := cipher.NewCBCDecrypter(block, []byte(initialVector))
	decrypted := make([]byte, len(crypt))
	ecb.CryptBlocks(decrypted, crypt)

	return PKCS5Trimming(decrypted)
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}
