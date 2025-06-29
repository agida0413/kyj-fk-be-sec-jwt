package com.kyj.fmk.sec.filter;

import com.kyj.fmk.sec.exception.SecErrCode;
import com.kyj.fmk.sec.jwt.JWTUtil;
import com.kyj.fmk.sec.model.res.SecurityResponse;
import com.kyj.fmk.sec.service.TokenService;
import com.kyj.fmk.core.util.CookieUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

@RequiredArgsConstructor
public class CustomLogoutFilter extends GenericFilterBean {

    private final JWTUtil jwtUtil;
    private final TokenService tokenService;


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {


        String requestUri = request.getRequestURI();//요청의 request url

        //api 요청이 /api/logout 이 아닐경우 다음필터로 넘김
        if (!requestUri.matches("^\\/api/v1/member/logout$")) {

            filterChain.doFilter(request, response);
            return;
        }
        String requestMethod = request.getMethod(); //post? get? put?

        if (!requestMethod.equals("POST")) {
            //만약 post 요청이 아닐경우 다음 필터로 넘김
            filterChain.doFilter(request, response);
            return;
        }

        //쿠키에서 refresh토큰을 가져옴


        String refresh = null;

        try {
            //쿠키를 읽어오는 메서드
            refresh=(String) CookieUtil.getCookie("refresh", request);

        } catch (Exception e) {
            // TODO: handle exception
            //쿠키 읽는 과정 에러 발생시
            SecurityResponse.writeErrorRes(response, HttpStatus.INTERNAL_SERVER_ERROR, SecErrCode.SEC006);

            return;
        }
        //만약 refresh토큰이 없을 경우

        if (refresh == null) {

            SecurityResponse.writeErrorRes(response, HttpStatus.UNAUTHORIZED, SecErrCode.SEC002);
            return;
        }

        //유효기간 검증
        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {

            //refresh 쿠키제거메서드
            ResponseCookie responseCookie = CookieUtil.deleteCookie(refresh, "/");
            response.setHeader(HttpHeaders.SET_COOKIE,responseCookie.toString());

            SecurityResponse.writeErrorRes(response,HttpStatus.UNAUTHORIZED,SecErrCode.SEC007);  //세션이 만료되었습니다.

            return;
        }

        // 토큰이 refresh인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(refresh);
        if (!category.equals("refresh")) {

            SecurityResponse.writeErrorRes(response, HttpStatus.UNAUTHORIZED, SecErrCode.SEC002);
            return;

        }
        String usrId = jwtUtil.getUsrId(refresh); // 레디스 키값
        //DB에 저장되어 있는지 확인
        Boolean isExist = tokenService.isExist(usrId,refresh);
        if (!isExist) {

            //refresh 쿠키제거메서드
            ResponseCookie responseCookie = CookieUtil.deleteCookie(refresh, "/");
            response.setHeader(HttpHeaders.SET_COOKIE,responseCookie.toString());
            SecurityResponse.writeErrorRes(response, HttpStatus.UNAUTHORIZED, SecErrCode.SEC002);
            return;
        }

        //로그아웃 진행
        //Refresh 토큰 DB에서 제거

        tokenService.deleteRefresh(usrId, refresh);


        //refresh 쿠키제거메서드
        ResponseCookie responseCookie = CookieUtil.deleteCookie(refresh, "/");
        response.setHeader(HttpHeaders.SET_COOKIE,responseCookie.toString());

        //성공 응답값
        SecurityResponse.writeSuccessRes(response);
        return;
    }




}
