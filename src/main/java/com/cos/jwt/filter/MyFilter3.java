package com.cos.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    // doFilter 메서드는 요청과 응답을 처리하는 필터링 로직을 정의합니다.
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // 토큰 : cos
        // ID, PW 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답을 해줌.
        // 그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증하면 됨. (RSA, HS256)
        // POST 요청만 처리하도록 조건 설정
        if (req.getMethod().equals("POST")) {

            // POST 요청이 들어왔음을 로그에 기록
            System.out.println("POST 요청됨.");
            // Authorization 헤더에서 토큰 값을 가져옴
            String headerAuth = req.getHeader("Authorization");
            // Authorization 헤더의 값 출력
            System.out.println(headerAuth);
            // 필터1이 호출되었음을 콘솔에 출력합니다.
            System.out.println("필터3");

            // 토큰 값이 "cos"인지 검증
            if (headerAuth.equals("cos")) {
                // 인증 성공 시 다음 필터 또는 최종 자원으로 요청과 응답을 전달
                chain.doFilter(req, res);

            // 인증 실패 시 클라이언트에 응답
            }else {
                PrintWriter out = res.getWriter();
                // 인증 실패 메시지 출력
                out.println("인증 안됨.");
            }
        }
    }
}
