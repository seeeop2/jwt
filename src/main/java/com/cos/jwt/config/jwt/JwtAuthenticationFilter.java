package com.cos.jwt.config.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// JwtAuthenticationFilter 클래스는 스프링 시큐리티의 UsernamePasswordAuthenticationFilter를 확장함
// /login 요청(POST)을 통해 username과 password를 전송하면 이 필터가 활성화됨
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // 인증 매니저를 주입받음
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        // 로그인 시도 로그 출력
        System.out.println("JwtAuthenticationFilter : 로그인 시도중");
        
        // 부모 클래스의 attemptAuthentication() 메서드를 호출
        return super.attemptAuthentication(request, response);
    }
}
