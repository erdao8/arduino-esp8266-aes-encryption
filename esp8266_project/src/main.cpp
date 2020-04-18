#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266mDNS.h>
#include <ArduinoJson.h>


#define DEBUG

#ifdef ESP8266
extern "C"
{
#include "user_interface.h"
}
#endif


#include "AES.h"
#include "base64.h"
#include "AES_config.h"


//加密与解密

uint8_t getrnd() {
    uint8_t really_random = *(volatile uint8_t *)0x3FF20E44;
    return really_random;
}

//生成随机初始化向量
void gen_iv(byte  *iv) {
    for (int i = 0 ; i < N_BLOCK ; i++ ) {
        iv[i]= (byte) getrnd();
    }
}

//加密    aes128  CBC  pkcs7填充  随机IV
//输入：Str: 明文 Str: 密码
//返回：Str: {"iv":"随机IV","msg":"密文"}
//注意：如果加密崩溃，适当增加缓存，缓存一定要在堆上申请。
String do_encrypt(String msg, byte *key)
{
	size_t encrypt_size_len = 2000;				//缓存长度
	DynamicJsonDocument root(1024);		//
    byte my_iv[N_BLOCK] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

	char *b64data = new char[encrypt_size_len];	//开辟一个数组
	byte *cipher = new byte[encrypt_size_len];	//为密文开辟一个数组

    AES aes;

    aes.set_key(key , sizeof(key));  	// 设置全局定义的密钥
    // gen_iv(my_iv);         				// 产生随机IV

	// 将缓冲区中的所有字节设置为0
    memset(b64data, 0, encrypt_size_len);

    //将IV进行base64编码
	base64_encode(b64data, (char *)my_iv, N_BLOCK);
	root["iv"] = String(b64data);

	// 将缓冲区中的所有字节设置为0
    memset(b64data, 0, encrypt_size_len);
    memset(cipher, 0, encrypt_size_len);

    //将msg进行base64编码
    int b64len = base64_encode(b64data, (char *)msg.c_str(), msg.length());

    //加密 使用AES128，密钥和IV，CBC和pkcs7填充
    aes.do_aes_encrypt((byte *)b64data, b64len , cipher, key, 128, my_iv);
	aes.clean();	//清理缓存中的密码

	// 将缓冲区中的所有字节设置为0
    memset(b64data, 0, encrypt_size_len);

    //将加密数据进行base64编码
	base64_encode(b64data, (char *)cipher, aes.get_size());
	root["msg"] = String(b64data);

	String JsonBuff;
	serializeJson(root, JsonBuff);
	root.clear();
	// 将缓冲区中的所有字节设置为0
    // memset(b64data, 0, sizeof(b64data));
    // memset(cipher, 0, sizeof(cipher));
	delete [] b64data;
	delete [] cipher;

    return JsonBuff;
}

//解密    aes128  CBC  pkcs7填充
//输入：Str: {"msg":"密文","iv":"随机IV"}
//返回：Str: 明文 Str: 密码
String do_decrypt(String CipherJson, byte *key, size_t len)
{
	DynamicJsonDocument root(len + 50);   //

	DeserializationError error = deserializeJson(root, CipherJson); 		//反序列化JSON数据

    //检查反序列化是否成功
    if (!error) 
    {
		byte my_iv[N_BLOCK] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		char my_iv_char[50];
		size_t encrypt_size_len = 2000;				//缓存长度

		char *b64data = new char[encrypt_size_len]; //开辟一个数组
		byte *cipher = new byte[encrypt_size_len]; //为密文开辟一个数组
		char *plain_msg = new char[encrypt_size_len]; //为明文开辟一个数组

		AES aes;

		String my_iv_str = root["iv"];
		String CipherText = root["msg"];

		root.clear();

		// 将缓冲区中的所有字节设置为0
		memset(b64data, 0, encrypt_size_len);

		memset(my_iv_char, 0, sizeof(my_iv_char));

		CipherText.toCharArray(b64data, CipherText.length()+1);
		my_iv_str.toCharArray(my_iv_char, my_iv_str.length()+1);

		base64_decode((char *)my_iv, my_iv_char, strlen(my_iv_char));

		// 将缓冲区中的所有字节设置为0
		memset(cipher, 0, encrypt_size_len);

		//加密数据的base64解码
		int cipherlen = base64_decode((char *)cipher, b64data, strlen(b64data));

		// 将缓冲区中的所有字节设置为0
		memset(b64data, 0, encrypt_size_len);

		//解密
		aes.set_key( key , sizeof(key));  // Get the globally defined key 获取全局定义的密钥
		aes.do_aes_decrypt(cipher, cipherlen, (byte *)b64data, key, 128, my_iv);
		aes.unpadPlaintext((byte *)b64data, aes.get_size());			//去掉填充
		aes.clean();	//清理缓存中的密码
		
		//base64解码
		memset(plain_msg, 0, encrypt_size_len);

		base64_decode(plain_msg, b64data, strlen(b64data));
		String plain_msg_str = String(plain_msg);

		delete [] b64data;
		delete [] cipher;
		delete [] plain_msg;

		return plain_msg_str;
    }

	root.clear();
    return "ERROR";
}





void setup() {
    Serial.begin(115200);
    Serial.println(" ");  


    //AES密钥。请注意，这与在Node-J端、python端使用的相同，十六进制字节。
    //iv现在默认为{ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}，可以使用随机生成。
    byte key[] = { 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48 };


    //加密
    Serial.println("----->>>>> Start encryption <<<<<-----");
    String msg = "Hello Word";
    Serial.println("msg:" + msg);
    String data = do_encrypt(msg, key);
    Serial.println("Encrypted data:" + data);

    //解密
    Serial.println("----->>>>> Start decrypting <<<<<-----");
    Serial.println("Encrypted data:" + data);
    Serial.println("Decrypted data:" + do_decrypt(data, key, 1000));

////////////////////////////////////////////////////////////////
    //加密
    Serial.println("----->>>>> Start encryption <<<<<-----");
    String msg1 = "Hello Word Hello Word";
    Serial.println("msg1:" + msg1);
    String data1 = do_encrypt(msg1, key);
    Serial.println("Encrypted data:" + data1);

    //解密
    Serial.println("----->>>>> Start decrypting <<<<<-----");
    Serial.println("Encrypted data:" + data1);
    Serial.println("Decrypted data:" + do_decrypt(data1, key, 1000));


}

void loop() {
    // put your main code here, to run repeatedly:
    while (1)
    {
        delay(1);
    }
}

