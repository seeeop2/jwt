package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {

        // CORS 설정을 위한 UrlBasedCorsConfigurationSource 객체 생성
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // CORS 설정을 위한 CorsConfiguration 객체 생성
        CorsConfiguration config = new CorsConfiguration();
        // 나의 서버가 응답할 때 JSON을 자바스크립트에서 처리할 수 있게 할지를 설정하는 것
        // 서버가 응답할 때 자격 증명(쿠키, 인증 헤더 등)을 포함한 요청을 허용할지를 설정
        // true일 경우, AJAX 요청에서 자격 증명을 포함할 수 있으며, false일 경우 포함할 수 없음
        config.setAllowCredentials(true);
        // 모든 IP에 응답을 허용함.
        config.addAllowedOrigin("*");
        // 모든 Header에 응답을 허용함.
        config.addAllowedHeader("*");
        // 모든 GET, POST, PATCH, DELETE에 응답을 허용함.
        config.addAllowedMethod("*");
        // "/api/**" 경로에 대한 CORS 설정 등록
        // 이 경로에 대한 요청에 대해 위에서 설정한 CORS 정책을 적용
        source.registerCorsConfiguration("/api/**", config);

        // 설정한 CORS 필터를 반환
        return new CorsFilter(source);
    }
}
