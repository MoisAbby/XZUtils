package com.daxian;

import org.apache.commons.net.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class AESUtil {

    public static byte[] getKeys(String data){
        try {
            // 创建AES的Key生产者
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            // 利用用户密码作为随机数初始化出128位的key生产者
            //SecureRandom 是生成安全随机数序列，password.getBytes() 是种子，只要种子相同，序列就一样，密钥也一样
            kgen.init(128, new SecureRandom(data.getBytes()));
            // 根据用户密码，生成一个密钥
            SecretKey secretKey = kgen.generateKey();
            byte[] key = secretKey.getEncoded();
            return key;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.out.println("没有此算法");
        }
        return null;
    }

    public static byte[] getKeys(){
        try {
            // 创建AES的Key生产者
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            // 利用用户密码作为随机数初始化出128位的key生产者
            //SecureRandom 是生成安全随机数序列，password.getBytes() 是种子，只要种子相同，序列就一样，密钥也一样
            kgen.init(128);
            // 根据用户密码，生成一个密钥
            SecretKey secretKey = kgen.generateKey();
            byte[] key = secretKey.getEncoded();
            return key;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.out.println("没有此算法");
        }
        return null;
    }

    /**
     * @param content
     * @param secretkey
     * @return
     */
    public static byte[] encrypt(String content, byte[] secretkey) {
        try {
            // 转换为AES专用密钥
            SecretKeySpec key = new SecretKeySpec(secretkey, "AES");

            Cipher cipher = Cipher.getInstance("AES");// 创建密码器
            byte[] byteContent = content.getBytes("utf-8");
            cipher.init(Cipher.ENCRYPT_MODE, key);// 初始化为加密模式的密码器
            byte[] result = cipher.doFinal(byteContent);// 加密
            return result;

        } catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] decrypt(byte[] content, SecretKey secretKey) {
        try {
            byte[] enCodeFormat = secretKey.getEncoded();
            // 转换为AES专用密钥
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
            // 创建密码器
            Cipher cipher = Cipher.getInstance("AES");
            // 初始化为解密模式的密码器
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] result = cipher.doFinal(content);
            // 明文
            return result;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] decrypt(byte[] content, byte[] secretKey) {
        try {
            // 转换为AES专用密钥
            SecretKeySpec key = new SecretKeySpec(secretKey, "AES");
            // 创建密码器
            Cipher cipher = Cipher.getInstance("AES");
            // 初始化为解密模式的密码器
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] result = cipher.doFinal(content);
            // 明文
            return result;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    public static void main(String[] args) {
        String content = "我是-冬竹";
        String password = "767";
        System.out.println("加密之前：" + content);

        byte[] key = getKeys();

        // 加密
        byte[] encrypt = AESUtil.encrypt(content, key);
        System.out.println("加密后的内容：" + Base64.encodeBase64URLSafeString(encrypt));

        // 解密
        byte[] decrypt = AESUtil.decrypt(encrypt, key);
        System.out.println("解密后的内容：" + new String(decrypt));
    }
}


















