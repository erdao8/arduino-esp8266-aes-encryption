//npm install --save-dev crypto-js

var CryptoJS = require("crypto-js");


var esp8266_data = JSON.parse('{"iv":"AAAAAAAAAAAAAAAAAAAAAA==","msg":"78h0suF+halbsnXxONoOq6sYr9xy7KQd3vBbmw/ilfA="}')

console.log("上传的数据: ", esp8266_data);

// 解密测试


// 要使用的AES加密/解密密钥。
var AESKey = '48484848484848484848484848484848';

// Base64解码到hex
var plain_iv =  new Buffer( esp8266_data.iv , 'base64').toString('hex');
console.log("plain_iv: ", plain_iv);


////
var plain_msg =  new Buffer( esp8266_data.msg , 'base64').toString('hex');
console.log("plain_msg: ", plain_msg);

////
var iv = CryptoJS.enc.Hex.parse( plain_iv );
var key= CryptoJS.enc.Hex.parse( AESKey );

console.log("密钥: ", AESKey.toString('ascii'));


console.log("----->>>>>解密：<<<<<-----");


// var srcs = CryptoJS.enc.Base64.stringify(plain_msg);
var b64_msg = new Buffer(plain_msg, 'hex').toString('base64');

console.log("b64_msg: ", b64_msg);

// 解密
var mybytes  = CryptoJS.AES.decrypt( b64_msg, key , { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 } );


var decoded_b64msg = mybytes.toString(CryptoJS.enc.Utf8);
console.log("明文的base64编码: ", decoded_b64msg.toString());


//Base64解码到ascii
var decoded_msg = new Buffer( decoded_b64msg , 'base64').toString('ascii');

console.log("明文: ", decoded_msg);

//////////////////////////////////////////////////////////////////////////////
console.log("\n\n----->>>>>加密：<<<<<-----");

// 加密测试

decoded_msg = 'Hello Word';

//msg的base64编码
var b64_msg = new Buffer(decoded_msg, 'ascii').toString('base64');
console.log("msg的base64编码: ", b64_msg);

// 加密

var key= CryptoJS.enc.Hex.parse( AESKey );

var encryptedData = CryptoJS.AES.encrypt(b64_msg, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });

var encryptedBase64Str = encryptedData.toString();
console.log("AES加密: ", encryptedBase64Str, "\n");

var esp8266_obj = {"iv":" ","msg":" "};

esp8266_obj.iv = esp8266_data.iv;
esp8266_obj.msg = encryptedBase64Str;

console.log("esp8266_JSON:", esp8266_obj, "\n");

var esp8266_JSON = JSON.stringify(esp8266_obj);

console.log(esp8266_JSON, "\n");