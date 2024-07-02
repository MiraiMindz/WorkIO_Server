package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	_ "github.com/joho/godotenv/autoload"
	"github.com/youmark/pkcs8"
)

func LoadPrivateKey(keyName, password string) (*rsa.PrivateKey) {
	privateKeyPEM := os.Getenv(keyName)
	privBlock, _ := pem.Decode([]byte(privateKeyPEM))
	privKey, err := pkcs8.ParsePKCS8PrivateKeyRSA(privBlock.Bytes, []byte(password))
	if err != nil {
		fmt.Println(err.Error())
	}

	return privKey
}

func LoadPublicKey(keyName string) (*rsa.PublicKey) {
	publicKeyPEM := os.Getenv(keyName)
	pubBlock, _ := pem.Decode([]byte(publicKeyPEM))
	pubParseResult, _ := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	pubKey := pubParseResult.(*rsa.PublicKey)
	return pubKey
}

func Encrypt(publicKey *rsa.PublicKey, data []byte) []byte {
	cipherData, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, publicKey, data, nil)
	if err != nil {
		fmt.Println(err.Error())
	}

	return cipherData
}

func Decrypt(privateKey *rsa.PrivateKey, encryptedData []byte) []byte {
	plainData, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, privateKey, encryptedData, nil)
	if err != nil {
		fmt.Println(err.Error())
	}

	return plainData
}

func DecodeBase64(data string) []byte {
	decodedData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	return decodedData
}

func EncodeBase64(data []byte) string {
	encodedData := base64.StdEncoding.EncodeToString(data)

	return encodedData
}

func DecryptFromEncryptTo(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, data []byte) []byte {
	decData := Decrypt(privateKey, data)
	encData := Encrypt(publicKey, decData)
	return encData
}

func DecodeDecrypt(privateKey *rsa.PrivateKey, data string) []byte {
	decodedData := DecodeBase64(data)
	decryptedData := Decrypt(privateKey, decodedData)
	return decryptedData
}

func EncryptEncode(publicKey *rsa.PublicKey, data []byte) string {
	encryptedData := Encrypt(publicKey, data)
	encodedData := EncodeBase64(encryptedData)
	return encodedData
}

func DecodeDecryptFromEncryptEncodeTo(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, data string) string {
	decryptedDecodedData := DecodeDecrypt(privateKey, data)
	encryptedEncodedData := EncryptEncode(publicKey, decryptedDecodedData)
	return encryptedEncodedData
}

func EncryptAESGCM(key, plaintext []byte) ([]byte) {
    block, err := aes.NewCipher(key)
    if err != nil {
        log.Fatalln(err.Error())
    }

    nonce := make([]byte, 12) // AES-GCM standard nonce size is 12 bytes
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalln(err.Error())
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
		log.Fatalln(err.Error())
    }

    ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
    return append(nonce, ciphertext...)
}

func DecryptAESGCM(key, ciphertext []byte) ([]byte) {
    block, err := aes.NewCipher(key)
    if err != nil {
		log.Fatalln(err.Error())
    }

    if len(ciphertext) < 12 {
		log.Fatalln(errors.New("ciphertext too short"))
    }

    nonce, ciphertext := ciphertext[:12], ciphertext[12:]

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
		log.Fatalln(err.Error())
    }

    plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
		log.Fatalln(err.Error())
    }

    return plaintext
}
