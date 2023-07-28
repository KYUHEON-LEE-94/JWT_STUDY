package com.example.security.jwt.account.service;

import com.example.security.jwt.account.domain.Account;
import com.example.security.jwt.account.domain.AccountAdapter;
import com.example.security.jwt.account.repository.AccountRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserDetailServiceImpl implements UserDetailsService {
    private final AccountRepository accountRepository;

    public UserDetailServiceImpl(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

    //  이 메서드는 사용자 이름을 기반으로 사용자 정보를 조회하고, 해당 정보를 UserDetails 인터페이스를 구현한 객체로 반환
    @Override
    @Transactional
    public UserDetails loadUserByUsername(final String username) {
        Account account = accountRepository.findOneWithAuthoritiesByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(username + " -> 데이터베이스에서 찾을 수 없습니다."));

        if(!account.isActivated()) throw new RuntimeException(account.getUsername() + " -> 활성화되어 있지 않습니다.");
        return new AccountAdapter(account);
    }
}
