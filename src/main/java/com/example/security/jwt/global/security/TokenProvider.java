package com.example.security.jwt.global.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;


// JWT 토큰 생성, 토큰 복호화 및 정보 추출, 토큰 유효성 검증의 기능이 구현된 클래스
public class TokenProvider {
    protected final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

    protected static final String AUTHORITIES_KEY = "auth";

    protected final String secret;
    protected final long tokenValidityInMilliseconds;

    protected Key key;

    //생성자
    public TokenProvider(String secret, long tokenValidityInSeconds) {
        this.secret = secret; // JWT 서명에 사용될 비밀키
        this.tokenValidityInMilliseconds = tokenValidityInSeconds * 1000; //1일

        //시크릿 값을 decode해서 키 변수에 할당
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        logger.debug("[TokenProvider] keyBytes: {}", keyBytes);
        this.key = Keys.hmacShaKeyFor(keyBytes); //HMAC-SHA 알고리즘에 사용되는 Key를 생성
        logger.debug("[TokenProvider] this.key: {}", this.key);
        //일반적으로 메시지 인증을 위해 사용되는 해시 기반의 메시지 인증코드.
    }

    // 인증 정보를 받아서 토큰 생성
    public String createToken(Authentication authentication) {
        //사용자 권한 정보를 추출하여 문자열로 만든다.
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(",")); // , 를 기준으로 String
        logger.debug("[createToken] authorities: {}", authorities);

        long now = (new Date()).getTime();
        Date validity = new Date(now + this.tokenValidityInMilliseconds); //유효기간 오늘 + 1일

        String jwts = Jwts.builder() //creating instances of JWT interfaces
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(validity)
                .compact();
        logger.debug("[createToken] jwts: {}", jwts);
        return jwts;

    }

    // JWT 토큰을 해석하여 사용자의 권한 정보를 추출후, 이를 Spring Security가 이해할 수 있는 형태로 변환하여 Authentication 객체를 생성합니다.
    // 이후 이 Authentication 객체를 사용하여 사용자를 인증하고 인가하는데 활용
    public Authentication getAuthentication(String token) {
        //token을 해석하기 위해 parseClaimsJws를 하고 파서에 서명키를 설정하여 token을 파싱
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
        logger.debug("[createToken] claims: {}", claims);

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(",")) //, 를 기준으로 split
                        .map(SimpleGrantedAuthority::new) //SimpleGrantedAuthority 객체로 변환. spring-security에서 사용되는 권한 정보 객체
                        .collect(Collectors.toList());
        logger.debug("[createToken] authorities: {}", authorities);

        // DB를 거치지 않고 토큰에서 값을 꺼내 바로 시큐리티 유저 객체를 만들어 Authentication을 만들어 반환하기에 유저네임, 권한 외 정보는 알 수 없다.
        User principal = new User(claims.getSubject(), "", authorities);
                                    //사용자 이름 , 비밀번호, 권한 - 토큰에서 값을 꺼내서 바로 시큐리티 유저 객체를 생성해서 반환
        return new UsernamePasswordAuthenticationToken(principal, token, authorities); //spring security의 Authentication 인터페이스를 구현하는 클래스로, 인증 정보를 나타냅니다.
    }

    // 토큰 유효성 검사
    public boolean validateToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            logger.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            logger.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            logger.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            logger.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }
}