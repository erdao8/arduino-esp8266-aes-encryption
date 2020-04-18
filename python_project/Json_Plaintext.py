#!/usr/bin/env python
# -*- coding: utf-8 -*-

# python -m pip install pycryptodome

""" 
@version: v1.0 
@author: erdao 
@contact: 
@software:  VSCode
@file: Json_Plaintext.py 
@time: 2019/12/11 14:35 
@describe: 加密与解密
"""

import sys
import json
import base64
import random           # 导入 random(随机数) 模块
from Crypto.Cipher import AES


#####################################################################

# 全局变量
AES128_key = '48484848484848484848484848484848'         # 密钥

#####################################################################


class AESEncrypter(object):
    def __init__(self, key, iv=None):
        self.key = key
        self.iv = iv if iv else bytes(key[0:16], 'utf-8')

    # 填充
    def _pad(self, text):
        text_length = len(text)
        padding_len = AES.block_size - int(text_length % AES.block_size)
        if padding_len == 0:
            padding_len = AES.block_size
        t2 = chr(padding_len) * padding_len
        t2 = t2.encode('utf-8')
        # print('text ', type(text), text)
        # print('t2 ', type(t2), t2)
        t3 = text + t2
        return t3

    # 去除填充
    def _unpad(self, text):
        text_length = len(text)
        padding_len = int(text_length % AES.block_size)
        if padding_len != 0:
            pad = ord(text[-1])
            return text[:-pad]
        else:
            return text

    # 纠正解密后的base64编码结尾缺失等号
    def _decode_base64(self, data):
        """
        Decode base64, padding being optional.
        :param data: Base64 data as an ASCII byte string
        :returns: The decoded byte string.
        """
        missing_padding = len(data) % 4
        if missing_padding != 0:
            data += b'='* (4 - missing_padding)
        return base64.b64decode(data)

    # 加密
    def encrypt(self, raw):
        raw = raw.encode('utf-8')
        raw = self._pad(raw)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        encrypted = cipher.encrypt(raw)
        return base64.b64encode(encrypted).decode('utf-8')

    # 解密
    def decrypt(self, enc):
        enc = enc.encode("utf-8")
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        decrypted = cipher.decrypt(enc)
        decrypted = self._unpad(decrypted.decode('utf-8'))
        decrypted = self._decode_base64(decrypted.encode('utf-8')).decode('utf-8')
        return decrypted


# 由密文JSON到明文
def JsonToPlaintext(esp8266_json):
    try:
        esp8266_data = json.loads(esp8266_json)
    except Exception as e:
        print('解析JSON失败，字符串:{},错误：{}'.format(esp8266_data, e))
        return
    iv = base64.b64decode(esp8266_data['iv'])                               # base64解码
    cipher = AESEncrypter(bytes.fromhex(AES128_key), iv)        
    return cipher.decrypt(esp8266_data['msg'])                              # 已验证


# 由明文到密文JSON
def PlaintextToJson(Plaintext):
    # esp8266_iv=''
    # for i in range(32):
    #     esp8266_iv += (random.choice('0123456789abcdef'))                   # 在 0-9 a-f 中随机凑32个字符
    esp8266_iv = '00000000000000000000000000000000'
    iv = bytes.fromhex(esp8266_iv)                                          # 转成16个16进制数，用作IV
    esp8266_iv = str(base64.b64encode(iv),'utf-8')                          # iv的base64编码
    b64msg = base64.b64encode(Plaintext.encode('utf-8')).decode('utf-8')    # 明文的base64编码
    print('b64msg: %s' % b64msg)                                          # 已验证
    cipher = AESEncrypter(bytes.fromhex(AES128_key), iv)                    # 加密
    encrypted = cipher.encrypt(b64msg)
    # print('Encrypted: %s' % encrypted)                                    # 已验证
    esp8266_send_json = {"iv":"%s" % esp8266_iv,"msg":"%s" % encrypted}     # 构造JSON
    return json.dumps(esp8266_send_json)                                    # 已验证


###
#打印16进制数据 测试用
def print_hex(bytes):
    l = [hex(int(i)) for i in bytes]
    print(" ".join(l))
###



if __name__ == "__main__":
    try:
        # for AES test

        print('解密测试：')
        esp8266_data = '{"iv":"AAAAAAAAAAAAAAAAAAAAAA==","msg":"VyIOXsJw4/wu18rfsOuWES2PRIcEmd/d2YBO8uf4GWI="}'
        print('密文: %s' % esp8266_data)
        print('Decrypted: %s' % JsonToPlaintext(esp8266_data))

#####################################################################

        print('加密测试：')
        msg = 'Hello Word Hello Word'
        print('esp8266 json: %s' % PlaintextToJson(msg))

#####################################################################

    except KeyboardInterrupt:
        sys.exit(0)

