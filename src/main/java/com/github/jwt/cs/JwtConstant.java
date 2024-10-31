package com.github.jwt.cs;

/**
 * @className: JwtConstant
 * @description: JWT 常量类
 * @version: V1.0
 */
public final class JwtConstant {
    // 加密算法
    public static final String ALGORITHM_NAME = "RSA";

    public static final String MD5_RSA = "MD5withRSA";

    public static final String JWT_PAYLOAD_USER_KEY = "UserInfo";

    public static final String TOKEN_HEADER = "Authorization";

    public static final String TOKEN_PREFIX = "Bearer ";
}
