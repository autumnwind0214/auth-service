package com.autumn.auth.config;

import com.autumn.auth.handler.MyAccessDeniedHandler;
import com.autumn.auth.handler.MyAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author autumn
 * @description 资源服务器SpringSecurity配置
 * @date 2025年02月11日
 * @version: 1.0
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true)
public class ResourceServerConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests((authorizeHttpRequests) -> authorizeHttpRequests
                        // 所有的访问都需要通过身份认证
                        .anyRequest().authenticated()
                )
                // 使用jwt处理接收到的access token
                .oauth2ResourceServer((oauth2ResourceServer) -> oauth2ResourceServer
                        .jwt(Customizer.withDefaults())
                        // 自定义异常处理类
                        .authenticationEntryPoint(new MyAuthenticationEntryPoint())
                        .accessDeniedHandler(new MyAccessDeniedHandler())

                );

        return http.build();
    }
}
