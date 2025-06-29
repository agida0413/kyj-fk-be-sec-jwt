package com.kyj.fmk.sec.config;

import com.kyj.fmk.sec.filter.CustomLogoutFilter;
import com.kyj.fmk.sec.filter.JwtFilter;
import com.kyj.fmk.sec.filter.LoginFilter;
import com.kyj.fmk.sec.jwt.JWTUtil;
import com.kyj.fmk.sec.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private static final String API_BASE_URL = "api/v1/";

    List<String> publicUrls = List.of(
            "/index.html",
            "/css/**",
            "/js/**",
            "/images/**",
            "/favicon.ico",
            "/fonts/**",
            "/img/**",
            API_BASE_URL+"member/login"
    );



    private final AuthenticationConfiguration authenticationConfiguration;

    //JWTUtil 주입
    private final JWTUtil jwtUtil;
    private final TokenService tokenService;



    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }

    //암호화
//    @Bean
//    public BCryptPasswordEncoder bcryptPasswordEncoder() {
//
//        return new BCryptPasswordEncoder();
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder(); // {noop}, {bcrypt} 등 지원
    }
    //필터 및 시큐리티 설정
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors((corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {

                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration configuration = new CorsConfiguration();
                        // 여러 도메인 추가
                        configuration.setAllowedOrigins(Arrays.asList(
                                "http://localhost:3000"// 개발 환경 1
//                                "http://randchat.o-r.kr", // 실제 서버
//                                "https://randchat.o-r.kr" // 실제 서버 (HTTPS)
                        ));
                        configuration.setAllowedMethods(Collections.singletonList("*"));//모든메소드 허용
                        configuration.setAllowCredentials(true);
                        configuration.setAllowedHeaders(Collections.singletonList("*"));
                        configuration.setMaxAge(3600L);
                        //  configuration.setExposedHeaders(Collections.singletonList("access"));
                        return configuration;
                    }
                })));

        http
                .csrf((auth) -> auth.disable()); //jwt 사용으로 인한 disable

        http
                .formLogin((auth) -> auth.disable()); //jwt사용으로 인한 기본로그인폼  x

        http
                .httpBasic((auth) -> auth.disable());


        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers(publicUrls.toArray(new String[0])).permitAll()
                        .requestMatchers("/api/v1/member/logout").authenticated()
                        .anyRequest().authenticated());//나머지는 인증이 필요함

        //  JWTFilter 등록 = > 로그인 필터 전에 수행
        http
                .addFilterBefore(new JwtFilter(jwtUtil), LoginFilter.class);


        // 로그인필터를  UsernamePasswordAuthenticationFilter 위치에
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil, tokenService), UsernamePasswordAuthenticationFilter.class);

        //커스텀한 로그아웃 필터를 등록 =>기존 필터위치에
        http
                .addFilterBefore(new CustomLogoutFilter(jwtUtil, tokenService), LogoutFilter.class);

        // 세션방식 미사용
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
