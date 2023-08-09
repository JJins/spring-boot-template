package com.example.demo.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.util.Date;
import java.util.UUID;

@Slf4j
public class JwtUtil {

    public static final long EXPIRE_TIME = 30 * 60 * 1000;
    private static final String JWT_SECRET = UUID.randomUUID().toString();

    /**
     * token是否正确
     */
    public static boolean verify(String token, String username) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(JWT_SECRET);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withClaim("username", username)
                    .build();
            verifier.verify(token);

            return true;
        } catch (TokenExpiredException e) {
            log.warn("Token 校验失败: 已过期, {}", e.getMessage());
            return false;
        } catch (Exception exception) {
            log.warn("Token 校验失败: {}", exception.getMessage());
            return false;
        }
    }

    /**
     * @return token中包含的用户名
     */
    public static String getUsernameFromToken(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getClaim("username").asString();
        } catch (JWTDecodeException e) {
            return null;
        }
    }

    /**
     * 签名
     *
     * @param username 用户名
     * @return 加密的token
     */
    public static String sign(String username) {

        Date current_date = new Date(System.currentTimeMillis());
        Date expire_date = new Date(System.currentTimeMillis() + EXPIRE_TIME);
        Algorithm algorithm = Algorithm.HMAC256(JWT_SECRET);

        return JWT.create()
                .withClaim("username", username)
                .withIssuedAt(current_date)
                .withExpiresAt(expire_date)
                .sign(algorithm);

    }

    public static String getToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (!StringUtils.hasLength(authHeader)) return null;
        return authHeader.substring(7).trim();
    }

}
