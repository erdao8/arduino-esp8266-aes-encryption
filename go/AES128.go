package main

import (
	"encoding/base64"
	//"encoding/hex"
	"fmt"
	"github.com/ChengjinWu/aescrypto"
)

func main()  {
	///////////////////////////////////////////
	//加密
	///////////////////////////////////////////

	// 原文
	orgkey := "Hello Word"
	// key & iv
	aes_key := []byte{0x48,0x48,0x48,0x48,0x48,0x48,0x48,0x48,0x48,0x48,0x48,0x48,0x48,0x48,0x48,0x48}
	iv_key := []byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}

	fmt.Println("原文是 :", orgkey)

	fmt.Println("base 64 key/iv:", Base64Encode([]byte(iv_key)))

	//
	orgkey_base64 := Base64Encode([]byte(orgkey))
	fmt.Println("原文的base64编码:", orgkey_base64)
	//

	crypted, err := aescrypto.AesCbcPkcs7Encrypt([]byte(orgkey_base64), aes_key, iv_key)
	if err != nil {
		fmt.Println(err)
	}
	crypted_base64 := Base64Encode(crypted)
	fmt.Println("密文的base64是:", crypted_base64)

	///////////////////////////////////////////
	// 解密
	///////////////////////////////////////////
	data, err := aescrypto.AesCbcPkcs7Decrypt(Base64Dncode(crypted_base64), aes_key, iv_key)

	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("原文的base64编码是 :", string(data))

	fmt.Println("原文是 :", string(Base64Dncode(string(data))))

}

//base64编码
func Base64Encode(src []byte) string{
	return base64.StdEncoding.EncodeToString(src)
}

//base64解码
func Base64Dncode(src string) []byte{
	decodeBytes, err := base64.StdEncoding.DecodeString(src)
    if err != nil {
		fmt.Println(err)
    }
	return decodeBytes
}
