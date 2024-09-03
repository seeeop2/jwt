package com.cos.jwt.filter;

import javax.servlet.*;
import java.io.IOException;

public class MyFilter2 implements Filter {

    // doFilter 메서드는 요청과 응답을 처리하는 필터링 로직을 정의합니다.
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        // 필터2이 호출되었음을 콘솔에 출력합니다.
        System.out.println("필터2");

        // 다음 필터 또는 최종 자원으로 요청과 응답을 전달합니다.
        chain.doFilter(request, response);
    }
}
