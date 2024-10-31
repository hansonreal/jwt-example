package com.github.jwt;

import com.github.jwt.utils.Base64Util;
import com.github.jwt.utils.RSA256Util;
import org.junit.Test;

import java.security.KeyPair;

public class RSA256UtilTest {

    @Test
    public void testRSA() {
        try {
            // 生成密钥对
            KeyPair keyPair = RSA256Util.getKeyPair("demo", 1024);
            String privateKey = new String(Base64Util.encoder(keyPair.getPrivate().getEncoded()));
            String publicKey = new String(Base64Util.encoder(keyPair.getPublic().getEncoded()));
            System.out.println("私钥:" + privateKey);
            System.out.println("公钥:" + publicKey);
            // RSA加密
            String data = "123456";
            String encryptData = RSA256Util.encrypt(data, RSA256Util.getPublicKey(publicKey));
            System.out.println("加密后内容:" + encryptData);
            // RSA解密
            String decryptData = RSA256Util.decrypt(encryptData, RSA256Util.getPrivateKey(privateKey));
            System.out.println("解密后内容:" + decryptData);
            // RSA签名
            String sign = RSA256Util.sign(data, RSA256Util.getPrivateKey(privateKey));
            // RSA验签
            boolean result = RSA256Util.verify(data, RSA256Util.getPublicKey(publicKey), sign);
            System.out.print("验签结果:" + result);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.print("加解密异常");
        }
    }

}
