# arduino-esp8266-aes-encryption
多平台的AES加密验证

此仓库演示了如何在ESP8266上使用AES加密解密数据，并在其他平台Python、NodeJS、go平台进行了对比验证。
esp8266_project由VSCode中的PlatformIO插件创建。
```
加密过程：
1.随机生成iv（可选） 
2.对明文进行base64编码。（非必须）
3.将编码好的数据进行aes128加密。
4.将加密的数据再次进行base64编码。
5.对随机生成的iv也进行base64编码。（非必须）
6.将第四与五的结果构成JSON。（非必须）
```
#### esp8266的测试结果
![arduino_test](https://github.com/erdao8/arduino-esp8266-aes-encryption/blob/master/%E6%B5%8B%E8%AF%95%E7%BB%93%E6%9E%9C/arduino_test.PNG)

#### Python的测试结果

#### NodeJS的测试结果
使用```crypto-js```库。
![NodeJS_test](https://github.com/erdao8/arduino-esp8266-aes-encryption/blob/master/%E6%B5%8B%E8%AF%95%E7%BB%93%E6%9E%9C/NodeJS_test.PNG)

#### go的测试结果
使用```github.com/ChengjinWu/aescrypto```库。
![go_test](https://github.com/erdao8/arduino-esp8266-aes-encryption/blob/master/%E6%B5%8B%E8%AF%95%E7%BB%93%E6%9E%9C/go_test.PNG)
![go_test](https://github.com/erdao8/arduino-esp8266-aes-encryption/blob/master/%E6%B5%8B%E8%AF%95%E7%BB%93%E6%9E%9C/go_test2.PNG)
