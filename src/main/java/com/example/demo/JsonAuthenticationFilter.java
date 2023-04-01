package com.example.demo;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;
import java.time.OffsetDateTime;
import java.util.ArrayList;

public class JsonAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private AuthenticationManager authenticationManager;

    public JsonAuthenticationFilter(AuthenticationManager authenticationManager){

        // AuthenticationManagerの設定
        this.authenticationManager = authenticationManager;

        // ログインパスを設定
        setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login","POST"));
        // ログイン用パラメータの設定
        setUsernameParameter("username");
        setPasswordParameter("password");

        // ログイン成功時はtokenを発行してレスポンスにセットする
        this.setAuthenticationSuccessHandler((req,res,ex) -> {
            // トークンの作成
            String token = JWT.create()
                    .withIssuer("com.volkruss.toaru") //発行者
                    .withClaim("username", ex.getName()) //keyに対してvalueの設定。汎用的な様々な値を保持できる
                    .withExpiresAt(OffsetDateTime.now().plusMinutes(3).toInstant())
                    .withIssuedAt(OffsetDateTime.now().toInstant())
                    .sign(Algorithm.HMAC256("secret")); // 利用アルゴリズムを指定してJWTを新規作成

            res.setHeader("X-AUTH-TOKEN", token); // tokeをX-AUTH-TOKENというKeyにセットする
            res.setStatus(200);
        });

        // ログイン失敗時
        this.setAuthenticationFailureHandler((req,res,ex) -> {
            logger.info(ex.getMessage());
            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        });
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            ServletInputStream stream = request.getInputStream();
            // リクエストのjsonの値をUserFormにマッピングします。
            UserForm form = new ObjectMapper().readValue(request.getInputStream(), UserForm.class);
            // これでデフォルトのProviderを利用しつつ、ユーザーレコードの取得に関してはUserDetailsServiceの実装クラスのloadUserByUsernameを利用する
            return this.authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(form.getUsername(), form.getPassword(), new ArrayList<>())
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
