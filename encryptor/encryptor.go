package encryptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/md4"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
	mr "math/rand"
	"strings"
	"time"
)

type SSHAEncoder struct{}

type MD4Encoder struct{}

type AesEncoder struct{}

func (se SSHAEncoder) Encode(rawPass []byte) string {
	hash := makeSSHAHash(rawPass, makeSalt())
	b64 := base64.StdEncoding.EncodeToString(hash)
	return fmt.Sprintf("{SSHA}%s", b64)
}

func (se SSHAEncoder) Matches(encodedPass, rawPass []byte) bool {
	ep := string(encodedPass)[6:]
	hash, err := base64.StdEncoding.DecodeString(ep)
	if err != nil {
		return false
	}
	salt := hash[len(hash)-4:]

	sha := sha1.New()
	sha.Write(rawPass)
	sha.Write(salt)
	sum := sha.Sum(nil)

	if bytes.Compare(sum, hash[:len(hash)-4]) != 0 {
		return false
	}
	return true
}

func makeSalt() []byte {
	sbytes := make([]byte, 4)
	rand.Read(sbytes)
	return sbytes
}

func makeSSHAHash(pass, salt []byte) []byte {
	sha := sha1.New()
	sha.Write(pass)
	sha.Write(salt)

	h := sha.Sum(nil)
	return append(h, salt...)
}

func (me MD4Encoder) Encode(passwd []byte) string {
	enc := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	hasher := md4.New()
	t := transform.NewWriter(hasher, enc)
	t.Write(passwd)
	return strings.ToUpper(hex.EncodeToString(hasher.Sum(nil)))

}

func (me MD4Encoder) Matches(encodedPass, rawPass string) bool {
	sum := me.Encode([]byte(rawPass))
	if strings.Compare(sum, encodedPass) != 0 {
		return false
	}
	return true
}

// AES
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func aesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func (ae AesEncoder) Decrypt(pwd string, aeskey []byte) (string, error) {
	bytesPass, err := base64.StdEncoding.DecodeString(pwd)
	if err != nil {
		return "", err
	}
	tpass, err := aesDecrypt(bytesPass, aeskey)
	if err != nil {
		return "", err
	}

	return string(tpass), nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func aesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func (ae AesEncoder) Encrypt(result []byte, aeskey []byte) (string, error) {
	pass := result
	xpass, err := aesEncrypt(pass, aeskey)
	if err != nil {
		return "", err
	}
	pass64 := base64.StdEncoding.EncodeToString(xpass)
	return string(pass64), nil
}

func GenRandom(l int) []byte {
	NUmStr := "1234567890"
	CharStr := "ABCDEFGHIJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz"
	SpecStr := "+=-@#~.!%^*$"
	str := NUmStr + CharStr + SpecStr
	bytes := []byte(str)
	result := []byte{}
	r := mr.New(mr.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return result
}
