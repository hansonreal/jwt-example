package com.github.jwt;

import com.github.jwt.utils.Base64Util;
import com.github.jwt.utils.JwtUtil;
import com.github.jwt.utils.RSA256Util;
import org.junit.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class JwtUtilTest {

    @Test
    public void testJwt() {

        try {
            // 生成密钥对
            KeyPair keyPair = RSA256Util.getKeyPair("demo", 1024);
            String publicKeyStr = new String(Base64Util.encoder(keyPair.getPublic().getEncoded()));
            String privateKeyStr = new String(Base64Util.encoder(keyPair.getPrivate().getEncoded()));
            System.out.println("公钥:\n" + publicKeyStr);
            System.out.println("私钥:\n" + privateKeyStr);
            PublicKey publicKey = RSA256Util.getPublicKey(publicKeyStr);
            PrivateKey privateKey = RSA256Util.getPrivateKey(privateKeyStr);

            //后面可以扩展权限信息
            String userInfo = "{\n" +
                    "    \" name \": \" 张三 \",\n" +
                    "    \" age \": \" 25 \"\n" +
                    "}";
            System.out.println("用户信息:" + userInfo);

            // 生成token 30秒后失效
            String jwtToken = JwtUtil.generateTokenExpireInSeconds(userInfo, privateKey, 5);
            System.out.println("生成5秒后过期的Token:\n" + jwtToken);

            // 获取Jwt里面内容
            JwtUtil.Payload<String> infoFromToken = JwtUtil.getInfoFromToken(jwtToken, publicKey, String.class);
            String bodyFrom = infoFromToken.getUserInfo();
            System.out.println("JWT解析出来的用户数据:\n" + userInfo);

            //验证JWT是否过期
            boolean expiration = JwtUtil.isExpiration(jwtToken, publicKey);
            System.out.println("JWT是否过期:" + expiration);

            // 休眠6秒
            Thread.sleep(6 * 1000);
            boolean expiration2 = JwtUtil.isExpiration(jwtToken, publicKey);
            System.out.println("程序暂停6秒，测试JWT是否过期:" + expiration2);


        } catch (Exception e) {
            e.printStackTrace();
        }


    }


}
