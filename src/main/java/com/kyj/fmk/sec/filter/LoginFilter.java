package com.kyj.fmk.sec.filter;


import com.kyj.fmk.sec.exception.SecErrCode;
import com.kyj.fmk.sec.jwt.JWTUtil;
import com.kyj.fmk.sec.model.member.CustomUserDetails;
import com.kyj.fmk.sec.model.res.SecurityResponse;
import com.kyj.fmk.sec.service.TokenService;
import com.kyj.fmk.core.util.CookieUtil;
import io.jsonwebtoken.lang.Collections;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.stream.Collectors;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    //jwt
    private final JWTUtil jwtUtil;
    //액세스 토큰 재발급 서비스
    private final TokenService tokenService;
    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil,TokenService tokenService) {

        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.tokenService=tokenService;
        //로그인 api url
        setFilterProcessesUrl("/api/v1/member/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {



        String username=obtainUsername(request); //프론트엔드에서 username으로 formdata로 준값 읽기
        String password=obtainPassword(request); //프론트엔드에서 password로 formdata로 준값 읽기


        //아이디 , 패스원드  VALIDATION
        if(username==null || password == null || username.trim().equals("") || password.trim().equals("")){
            SecurityResponse.writeErrorRes(response, HttpStatus.UNAUTHORIZED,SecErrCode.SEC004);
        }


        //로그인을 위해  UsernamePasswordAuthenticationToken 에 정보를 담고 authenticate= > userdetailservice = > 인가 권한정보 없음
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, Collections.emptyList());

        return authenticationManager.authenticate(authToken);
    }


    //로그인 인증 성공시
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws  IOException {

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        
        String usrId= userDetails.getUsername();
        String nickname= userDetails.getNickname();
        String username =userDetails.getUsrNm();
        String sex = userDetails.getSex();
        String birth = userDetails.getBirth();
        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
        String roles = authorities.stream()
                .map(GrantedAuthority::getAuthority) // 예: "ROLE_USER"
                .collect(Collectors.joining(","));   // 콤마로 연결


        //String category,String username,String usrId,
        // String nickname,String sex,String birth, Long expiredMs
        //토큰 생성( 각토큰이름 + email+role+strIdNum + 유효기간 + 시크릿키(sha))
        String access = jwtUtil.createJwt("access", username, usrId,nickname, sex, birth,roles,300000L);//엑세스 토큰
        String refresh = jwtUtil.createJwt("refresh",  username, usrId,nickname, sex, birth,roles,86400000L); //리프레시 토큰


        //refresh토큰 레디스에 저장 = > 서버에서 제어권을 가지려고 ( 나중에 탈취당했을때에 대비하여)
        tokenService.addRefresh(usrId,refresh);

        //응답 설정
        response.setHeader("Authorization", "Bearer " + access);

        ResponseCookie cookie= CookieUtil.createCookie("refresh",refresh,604800,"/");

        //성공시 응답
        response.setHeader(HttpHeaders.SET_COOKIE,cookie.toString());

        SecurityResponse.writeSuccessRes(response);

    }


    //실패시
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws java.io.IOException {

            SecurityResponse.writeErrorRes(response,HttpStatus.UNAUTHORIZED,SecErrCode.SEC005);
    }




}