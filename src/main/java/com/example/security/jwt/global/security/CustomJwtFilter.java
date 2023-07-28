package com.example.security.jwt.global.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;

/***
 * 클라이언트 요청 시 JWT 인증을 하기 위해 설치하는 커스텀 필터로 UsernamePasswordAuthenticationFilter 이전에 실행
 *
 * 이전에 실행된다는 뜻은 JwtAuthenticationFilter를 통과하면 UsernamePasswordAuthenticationFilter 이후의 필터는 통과한 것으로 본다는 뜻이다.
 * 쉽게 말해서, Username + Password를 통한 인증을 Jwt를 통해 수행한다는 것이다.
 *
 * JWT 토큰을 인증하여 인증 정보를 SecurityContext에 저장하는 역할을 수행하는 커스텀 필터
 */
@Component
public class CustomJwtFilter extends GenericFilterBean {

    private static final Logger logger = LoggerFactory.getLogger(CustomJwtFilter.class);

    public static final String AUTHORIZATION_HEADER = "Authorization";

    private TokenProvider tokenProvider;

    public CustomJwtFilter(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    // 실제 필터링 로직은 doFilter 안에 들어가게 된다. GenericFilterBean을 받아 구현
    // Dofilter는 토큰의 인증정보를 SecurityContext 안에 저장하는 역할 수행
    // 현재는 jwtFilter 통과 시 loadUserByUsername을 호출하여 DB를 거치지 않으므로 시큐리티 컨텍스트에는 엔티티 정보를 온전히 가지지 않는다
    // 즉 loadUserByUsername을 호출하는 인증 API를 제외하고는 유저네임, 권한만 가지고 있으므로 Account 정보가 필요하다면 디비에서 꺼내와야함
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {

        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        String jwt = resolveToken(httpServletRequest);
        logger.debug("[doFilter] jwt: {}", jwt);
        String requestURI = httpServletRequest.getRequestURI();
        logger.debug("[doFilter] requestURI: {}", requestURI);
        // 유효성 검증
        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
            // 토큰에서 유저네임, 권한을 뽑아 스프링 시큐리티 유저를 만들어 Authentication 반환
            Authentication authentication = tokenProvider.getAuthentication(jwt);
            // 해당 스프링 시큐리티 유저를 시큐리티 건텍스트에 저장, 즉 디비를 거치지 않음
            SecurityContextHolder.getContext().setAuthentication(authentication);
            logger.debug("Security Context에 '{}' 인증 정보를 저장했습니다, uri: {}", authentication.getName(), requestURI);
        } else {
            logger.debug("유효한 JWT 토큰이 없습니다, uri: {}", requestURI);
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    // 헤더에서 토큰 정보를 꺼내온다.
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        logger.debug("[resolveToken] bearerToken: {}", bearerToken);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}