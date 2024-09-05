package com.cos.jwt.config.auth;

import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// http://localhost:8080/login 요청 시, 동작함.
// 하지만, formLogin을 Disable 해놨기에 동작을 안함.
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    // 사용자 이름으로 사용자를 로드하는 메서드
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailsService의 loadUserByUsername()");
        // username으로 사용자 엔티티를 조회
        User userEntity = userRepository.findByUsername(username);

        // 사용자 엔티티를 PrincipalDetails로 감싸서 반환
        return new PrincipalDetails(userEntity);
    }
}
