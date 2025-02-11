// package com.autumn.auth.config;
//
// import com.nimbusds.jose.jwk.JWKSet;
// import com.nimbusds.jose.jwk.RSAKey;
// import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
// import com.nimbusds.jose.jwk.source.JWKSource;
// import com.nimbusds.jose.proc.SecurityContext;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.core.annotation.Order;
// import org.springframework.http.MediaType;
// import org.springframework.security.config.Customizer;
// import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import org.springframework.security.core.userdetails.User;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import org.springframework.security.oauth2.core.AuthorizationGrantType;
// import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
// import org.springframework.security.oauth2.core.oidc.OidcScopes;
// import org.springframework.security.oauth2.jwt.JwtDecoder;
// import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
// import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
// import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
// import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
// import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
// import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
// import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
// import org.springframework.security.provisioning.InMemoryUserDetailsManager;
// import org.springframework.security.web.SecurityFilterChain;
// import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
// import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
//
// import java.security.KeyPair;
// import java.security.KeyPairGenerator;
// import java.security.interfaces.RSAPrivateKey;
// import java.security.interfaces.RSAPublicKey;
// import java.util.UUID;
//
// /**
//  * @author autumn
//  * @description spring security核心配置类
//  * @date 2025年02月01日
//  * @version: 1.0
//  */
// @Configuration
// @EnableWebSecurity
// // @EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true)
// public class SecurityConfigCopy {
//
//     private static final String CUSTOM_CONSENT_PAGE_URI = "/oauth2/consent";
//
//     private static final String CUSTOM_LOGIN_URI = "/login";
//
//     @Bean
//     @Order(1)
//     public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
//         // 配置默认的设置，忽略认证端点的csrf校验
//         OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//
//         http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
//                 // 开启OpenID Connect 1.0协议相关端点
//                 .oidc(Customizer.withDefaults())
//                 // 设置自定义用户确认授权页
//                 // .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI))
//         ;
//
//         http
//                 // 当未登录时访问认证端点时重定向至login页面
//                 .exceptionHandling((exceptions) -> exceptions
//                         .defaultAuthenticationEntryPointFor(
//                                 new LoginUrlAuthenticationEntryPoint(CUSTOM_LOGIN_URI),
//                                 new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
//                         )
//                 )
//                 // 使用jwt处理接收到的access token
//                 .oauth2ResourceServer((resourceServer) -> resourceServer
//                         .jwt(Customizer.withDefaults()));
//
//         return http.build();
//     }
//
//     /*
//      * Spring Security 过滤链配置（此处是纯Spring Security相关配置）
//      */
//     @Bean
//     @Order(2)
//     public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
//             throws Exception {
//         http
//                 .authorizeHttpRequests((authorize) -> authorize
//                         // 设置所有请求都需要认证，未认证的请求都会被重定向到login页面进行登录
//                         .anyRequest().authenticated()
//                 )
//                 // Form login handles the redirect to the login page from the
//                 // authorization server filter chain
//                 // 由Spring Security 过滤链中 UsernamePasswordAuthenticationFilter过滤器拦截处理“login”页面提交的登录信息
//                 .formLogin(Customizer.withDefaults());
//
//         return http.build();
//     }
//
//     /*
//      * Spring Security的配置
//      * 设置用户信息、校验用户名、密码
//      */
//     @Bean
//     public UserDetailsService userDetailsService() {
//         UserDetails userDetails = User.withDefaultPasswordEncoder()
//                 .username("admin")
//                 .password("111111")
//                 .roles("USER")
//                 .build();
//
//         // 基于内存的用户数据校验
//         return new InMemoryUserDetailsManager(userDetails);
//     }
//
//     /*
//      * 注册客户端信息
//      *
//      * 查询认证服务器信息
//      * http://127.0.0.1:9000/.well-known/openid-configuration
//      *
//      * 获取授权码
//      * http://localhost:9000/oauth2/authorize?response_type=code&client_id=oidc-client&scope=profile openid&redirect_uri=http://www.baidu.com
//      *
//      * 正常的流程是存在一个web前端页面提供给客户端进行注册，然后后端接口会将客户端注册信息保存到DB中，然后去查询DB，最后封装为一个RegisteredClient
//      */
//     @Bean
//     public RegisteredClientRepository registeredClientRepository() {
//         RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                 .clientId("oidc-client")
//                 // {noop}开头，表示“secret”以明文存储
//                 .clientSecret("{noop}secret")
//                 // 默认认证方式
//                 .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                 // 配置授权码模式、刷新令牌、客户端模式
//                 .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                 .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                 .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                 .redirectUri("http://spring-oauth-client:9001/login/oauth2/code/messaging-client-oidc")
//                 // 暂时还没有客户端服务，以免重定向跳转错误导致接收不到授权码
//                 .redirectUri("https://www.baidu.com")
//                 .postLogoutRedirectUri("http://127.0.0.1:8080/")
//                 // 设置客户端权限范围
//                 .scope(OidcScopes.OPENID)
//                 .scope(OidcScopes.PROFILE)
//                 // 客户端设置用户需要确认授权
//                 .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//                 .build();
//
//         // 配置基于内存的客户端信息
//         return new InMemoryRegisteredClientRepository(oidcClient);
//     }
//
//     /*
//      * 配置JWK，为JWK(id_token)提供加密密钥，用于加密/解密或签名/验签
//      */
//     @Bean
//     public JWKSource<SecurityContext> jwkSource() {
//         KeyPair keyPair = generateRsaKey();
//         RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
//         RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
//         RSAKey rsaKey = new RSAKey.Builder(publicKey)
//                 .privateKey(privateKey)
//                 .keyID(UUID.randomUUID().toString())
//                 .build();
//         JWKSet jwkSet = new JWKSet(rsaKey);
//         return new ImmutableJWKSet<>(jwkSet);
//     }
//
//     /*
//      * 生成RSA密钥对，给上面的jwtSource() 方法提供密钥对
//      */
//     private static KeyPair generateRsaKey() {
//         KeyPair keyPair;
//         try {
//             KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//             keyPairGenerator.initialize(2048);
//             keyPair = keyPairGenerator.generateKeyPair();
//         } catch (Exception ex) {
//             throw new IllegalStateException(ex);
//         }
//         return keyPair;
//     }
//
//     /*
//      * 配置jwt解析器
//      */
//     @Bean
//     public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
//         return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
//     }
//
//     /*
//      * 配置授权服务器请求地址
//      */
//     @Bean
//     public AuthorizationServerSettings authorizationServerSettings() {
//         // 什么都不配置，则使用默认地址
//         return AuthorizationServerSettings.builder().build();
//     }
// }
