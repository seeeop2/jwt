package com.cos.jwt.config;

import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter3;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // CORS 필터를 주입받음
    private final CorsFilter corsFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // SecurityContextPersistenceFilter 는 Security Filter Chain 중 가장 우선적으로 실행되는 필터임.
        // http.addFilterBefore() 메서드에 new MyFilter3(), SecurityContextPersistenceFilter.class 파라미터를 순서대로 대입하면
        // Security Filter Chain 이 실행되기 전에 MyFilter3이 실행됨.
        http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);

        // CSRF 보호 비활성화
        http.csrf().disable();

        // Session을 사용하지 않도록 설정함.
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // CORS 필터 추가
                .addFilter(corsFilter)
                // form 로그인 사용 안함.
                .formLogin().disable()
                // HTTP Basic 인증을 사용하지 않음
                .httpBasic().disable()
                // 요청에 대한 접근 제어를 시작
                .authorizeRequests()
                // 사용자 관련 API 경로
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                // 관리자 관련 API 경로
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                // 최상위 관리자 API 경로
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                // 위의 경로 외의 모든 요청 허용
                .anyRequest().permitAll();
    }
}
