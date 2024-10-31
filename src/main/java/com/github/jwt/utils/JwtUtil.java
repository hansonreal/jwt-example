package com.github.jwt.utils;

import com.github.jwt.cs.JwtConstant;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.joda.time.DateTime;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.UUID;

/**
 * @className: JwtUtil
 * @description: 生成token以及校验token相关方法
 * @version: V1.0
 */
public class JwtUtil {

    /**
     * 私钥加密token
     *
     * @param userInfo   载荷中的数据
     * @param privateKey 私钥
     * @param expire     过期时间，单位分钟
     * @return JWT
     */
    public static String generateTokenExpireInMinutes(Object userInfo,
                                                      PrivateKey privateKey,
                                                      int expire) {
        return Jwts.builder()
                .claim(JwtConstant.JWT_PAYLOAD_USER_KEY, JsonUtil.serialize(userInfo))
                .setId(createJTI())
                .setExpiration(DateTime.now().plusMinutes(expire).toDate())
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    /**
     * 私钥加密token
     *
     * @param userInfo   载荷中的数据
     * @param privateKey 私钥
     * @param expire     过期时间，单位秒
     * @return JWT
     */
    public static String generateTokenExpireInSeconds(Object userInfo,
                                                      PrivateKey privateKey,
                                                      int expire) {
        return Jwts.builder()
                .claim(JwtConstant.JWT_PAYLOAD_USER_KEY, JsonUtil.serialize(userInfo))
                .setId(createJTI())
                .setExpiration(DateTime.now().plusSeconds(expire).toDate())
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    /**
     * 公钥解析token
     *
     * @param token     用户请求中的token
     * @param publicKey 公钥
     * @return Claims
     */
    private static Claims parserToken(String token, PublicKey publicKey) {
        return Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token).getBody();
    }


    /**
     * 获取token中的用户信息
     *
     * @param token     用户请求中的令牌
     * @param publicKey 公钥
     * @return 用户信息
     */
    public static <T> Payload<T> getInfoFromToken(String token,
                                                  PublicKey publicKey,
                                                  Class<T> userType) {
        Claims body = parserToken(token, publicKey);
        Payload<T> claims = new Payload<>();
        claims.setId(body.getId());
        Object obj = body.get(JwtConstant.JWT_PAYLOAD_USER_KEY);
        T parse = JsonUtil.parse(obj.toString(), userType);
        claims.setUserInfo(parse);
        claims.setExpiration(body.getExpiration());
        return claims;
    }

    private static String createJTI() {
        return new String(Base64Util.encoder(UUID.randomUUID().toString().getBytes()));
    }

    // 是否已过期
    public static boolean isExpiration(String token, PublicKey publicKey) {
        try {
            Claims body = parserToken(token, publicKey);
            return body.getExpiration().before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        }
    }

    /**
     * 存放载体数据
     *
     * @param <T>
     */
    public static class Payload<T> {
        private String id;
        private T userInfo;
        private Date expiration;

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public T getUserInfo() {
            return userInfo;
        }

        public void setUserInfo(T userInfo) {
            this.userInfo = userInfo;
        }

        public Date getExpiration() {
            return expiration;
        }

        public void setExpiration(Date expiration) {
            this.expiration = expiration;
        }
    }
}
