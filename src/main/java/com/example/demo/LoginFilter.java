package com.example.demo;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;

public class LoginFilter extends OncePerRequestFilter {
    private final String secretKey = "secret";
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // headerからTokenを取得する
        String header = request.getHeader("X-AUTH-TOKEN");
        logger.info("header = " + header);
        //　チェック処理
        if(header == null || !header.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            logger.info("");
            return;
        }
        String token = header.substring(7);
        // Tokenの検証と認証を行う

        DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC256(secretKey))
                .acceptExpiresAt(1)
                .build().verify(token);
        // usernameの取得
        String username = decodedJWT.getClaim("username").toString();
        // ログイン状態を設定する
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(username,null,new ArrayList<>()));
        filterChain.doFilter(request,response);
    }
}
