package com.daxian;

import org.apache.commons.net.util.Base64;

public class AES_RSAUtil {

    public static void main(String[] args) throws Exception{
        /*模拟客户端*/
        String msg = "hello 冬竹";
        byte[] key = AESUtil.getKeys();//获取密钥的编码

        byte[] bytes = AESUtil.encrypt(msg,key);
        String seKey = Base64.encodeBase64URLSafeString(key);//转成字符串之后进行再加密
        RSAUtil.init();
        //RSA公钥 加密后的 AES密钥
        String encryptKey = RSAUtil.encryptByPublicKey(seKey,RSAUtil.getPublicKey(RSAUtil.keyMap.get("PUBLIC_KEY")));




        /*模拟服务端*/
        //解码AES密钥
        String aesKey = RSAUtil.decryptByPrivateKey(encryptKey,RSAUtil.getPrivateKey(RSAUtil.keyMap.get("PRIVATE_KEY")));
        //还原aesKey
        byte[] secretKey = Base64.decodeBase64(aesKey);
        String ming = new String(AESUtil.decrypt(bytes,secretKey));
        System.out.println(ming);

    }









}
