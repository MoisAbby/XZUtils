package com.daxian;

import org.apache.commons.net.util.Base64;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;

public class RSAUtil {

    public static String KEY_PAIRGENO = "RSA";
    public static String PUBLIC_KEY = "PUBLIC_KEY";
    public static String PRIVATE_KEY = "PRIVATE_KEY";
    public static final String CHARSET = "UTF-8";

    public static HashMap<String, String> keyMap = new HashMap<>(2);

    public static void init() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_PAIRGENO);
        keyPairGen.initialize(1024);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        String publicKey = getPublicKeyStr(keyPair.getPublic());
        String privateKey = getPrivateKeyStr(keyPair.getPrivate());

        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY,privateKey);
    }


    private static String getPrivateKeyStr(PrivateKey privateKey) throws Exception {
        return Base64.encodeBase64URLSafeString(privateKey.getEncoded());
    }

    private static String getPublicKeyStr(PublicKey publicKey) throws Exception {
        return Base64.encodeBase64URLSafeString(publicKey.getEncoded());
    }

    /**
     * 把字符串公钥转为 RSAPublicKey 公钥
     */
    public static RSAPublicKey getPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        //通过X509编码的Key指令获得公钥对象
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_PAIRGENO);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKey));
        RSAPublicKey key = (RSAPublicKey) keyFactory.generatePublic(x509KeySpec);
        return key;
    }

    /**
     * 把字符串私钥转为 RSAPrivateKey 私钥
     */
    public static RSAPrivateKey getPrivateKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        //通过PKCS#8编码的Key指令获得私钥对象
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_PAIRGENO);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKey));
        RSAPrivateKey key = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);
        return key;
    }

    /**
     * 公钥加密,  加密明文最大长度是117字节
     */
    public static String  encryptByPublicKey(String msg, RSAPublicKey publicKey) throws Exception{
        Cipher cipher = Cipher.getInstance(KEY_PAIRGENO);
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        int keySize = publicKey.getModulus().bitLength();//1024
        byte[] data = msg.getBytes(CHARSET);
        byte[] encryptedData = rsaSplitCode(cipher, data, Cipher.ENCRYPT_MODE, keySize);
        String mi= Base64.encodeBase64URLSafeString(encryptedData);
        return mi;


    }

    /*
     * 私钥解密，解密要求密文最大长度为128字节
     * */
    public static String decryptByPrivateKey(String rsaMsg, RSAPrivateKey privateKey) throws Exception{
        Cipher cipher = Cipher.getInstance(KEY_PAIRGENO);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        int keySize = privateKey.getModulus().bitLength();//长度是1024
        byte[] data = Base64.decodeBase64(rsaMsg);
        byte[] decryptedData = rsaSplitCode(cipher, data, Cipher.DECRYPT_MODE, keySize);
        String ming = new String(decryptedData, CHARSET);
        return ming;
    }

    /*私钥加密*/
    public static String encryptByPrivate(String msg, RSAPrivateKey privateKey) throws Exception{
        Cipher ciper = Cipher.getInstance(KEY_PAIRGENO);
        ciper.init(Cipher.ENCRYPT_MODE,privateKey);
        int keySize = privateKey.getModulus().bitLength();
        byte[] data = msg.getBytes(CHARSET);
        byte[] encryptedData = rsaSplitCode(ciper, data, Cipher.ENCRYPT_MODE,keySize);
        String mi = Base64.encodeBase64URLSafeString(encryptedData);
        return mi;
    }

    /*公钥解密*/
    public static String decrytByPublic(String msg, RSAPublicKey publicKey) throws Exception{
        Cipher ciper = Cipher.getInstance(KEY_PAIRGENO);
        ciper.init(Cipher.DECRYPT_MODE, publicKey);
        int keySize = publicKey.getModulus().bitLength();
        byte[] data = Base64.decodeBase64(msg);
        byte[] decryptedData = rsaSplitCode(ciper, data, Cipher.DECRYPT_MODE,keySize);
        String ming = new String(decryptedData,CHARSET);
        return ming;
    }



    private static byte[] rsaSplitCode(Cipher cipher, byte[] data,int opmode ,int keySize){
        int maxBlock = 0;
        if(opmode == Cipher.DECRYPT_MODE)
            maxBlock = keySize / 8;//解密要求最大长度是128
        else
            maxBlock = keySize / 8 -11; //加密要求最大长度是117

        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        try {
            while (inputLen - offSet > 0) {
                 if (inputLen - offSet > maxBlock) {
                     cache = cipher.doFinal(data, offSet, maxBlock);
                 } else {
                     cache = cipher.doFinal(data, offSet, inputLen - offSet);
                 }
                  out.write(cache, 0, cache.length);
                 i++;
                 offSet = i * maxBlock;
             }
            byte[] bytes = out.toByteArray();
            out.close();
            return bytes;
        } catch (Exception e) {
            throw new RuntimeException("加解密阀值为["+maxBlock+"]的数据时发生异常", e);
        }
    }





    public static void main(String[] args) throws Exception {
        init();
        String msg = "我是冬竹";
        System.out.println("公钥加密-私钥解密：");
        String mi  =  encryptByPublicKey(msg, getPublicKey(keyMap.get(PUBLIC_KEY)));
        System.out.println("密文：" + mi);

        String ming = decryptByPrivateKey(mi ,  getPrivateKey(keyMap.get(PRIVATE_KEY)));
        System.out.println("明文：" + ming);

        System.out.println("私钥加密-公钥解密：");
        String mi2 =  encryptByPrivate(msg, getPrivateKey(keyMap.get(PRIVATE_KEY)));
        System.out.println("密文：" + mi2);

        String ming2 = decrytByPublic(mi2 ,  getPublicKey(keyMap.get(PUBLIC_KEY)));
        System.out.println("明文：" + ming);
    }

}
