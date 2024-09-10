package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

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

        try {
            /*
            BufferedReader br = request.getReader();
            String input = null;
            while ((input = br.readLine()) != null) {
                System.out.println(input); // username={username}&password={password}
            }
            */

            // ObjectMapper는 JSON 데이터를 파싱하는 데 사용됨
            ObjectMapper om = new ObjectMapper();
            // 요청의 입력 스트림에서 JSON 데이터를 읽어 User 객체로 변환
            User user = om.readValue(request.getInputStream(), User.class);
            // 파싱된 사용자 정보를 출력
            System.out.println(user);

            // form 로그인의 경우 자동으로 토큰을 만들어주지만
            // form 로그인을 사용하지 않도록 설정했기에 직접 UsernamePasswordAuthenticationToken 생성
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행된 후,
            // 정상적으로 인증이 이루어지면 authentication 객체가 리턴됨
            // DB에 있는 username과 password가 일치하는지 확인
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // 인증된 사용자 정보를 PrincipalDetails에 저장
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

            // 로그인이 정상적으로 되었다는 뜻
            System.out.println("로그인 완료됨: " + principalDetails.getUser().getUsername());

            // authentication 객체가 session 영역에 저장을 해야하고, 그 방법이 return 해주면 됨.
            // 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하라고 하는 것임.
            // JWT 토큰을 사용하면서 세션을 만들 이유는 굳이 없으나, 권한 처리 때문에 session에 넣어줌.
            return authentication;

        } catch (IOException e) {
            // 예외 발생 시 스택 트레이스 출력
            e.printStackTrace();
        }

        // 인증 실패 시 null 리턴
        return null;
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면, successfulAuthentication 메서드가 실행됨.
    // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 됨.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        // 인증이 완료되었음을 알리는 로그 출력
        System.out.println("successfulAuthentication 실행됨: 인증이 완료되었다는 뜻임.");

        // 인증된 사용자의 정보를 PrincipalDetails에서 가져옴
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // JWT 토큰을 생성
        // RSA 방식 대신 HMAC 해시 암호 방식을 사용
        String jwtToken = JWT.create()
                // 토큰의 주제 설정
                .withSubject("cos토큰")
                // 토큰 만료 시간 설정
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
                // 사용자 ID를 클레임에 추가
                .withClaim("id", principalDetails.getUser().getId())
                // 사용자 이름을 클레임에 추가
                .withClaim("username", principalDetails.getUser().getUsername())
                // HMAC512 알고리즘으로 서명
                .sign(Algorithm.HMAC512("cos"))
                ;

        // 생성한 JWT 토큰을 Authorization 헤더에 추가하여 응답
        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
