package com.example.demo.config;

import com.example.demo.JsonAuthenticationFilter;
import com.example.demo.LoginFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authz -> authz
                .requestMatchers("/api/login").permitAll()
                .requestMatchers("/api/**").authenticated());
        http.addFilter(new JsonAuthenticationFilter(authentication -> authentication));
        http.addFilterAfter(new LoginFilter(),JsonAuthenticationFilter.class);
        http.csrf().ignoringRequestMatchers("/api/**");
        http.cors();
        return http.build();
    }

    // CORS設定を行うBean定義
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        var configuration = new CorsConfiguration();

        // Access-Control-Allow-Origin
        configuration.setAllowedOriginPatterns(List.of("*"));

        // Access-Control-Allow-Methods
        configuration.setAllowedMethods(List.of("*"));

        // Access-Control-Allow-Headers
        configuration.setAllowedHeaders(List.of("*"));

        // Access-Control-Allow-Credentials
        configuration.setAllowCredentials(true);

        configuration.setExposedHeaders(List.of("*"));

        var source = new UrlBasedCorsConfigurationSource();

        // COSR設定を行う範囲のパスを指定する。この例では全てのパスに対して設定が有効になる
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}
