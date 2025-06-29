package com.kyj.fmk.sec.filter;

import com.kyj.fmk.sec.exception.SecErrCode;
import com.kyj.fmk.sec.jwt.JWTUtil;
import com.kyj.fmk.sec.model.member.BaseMember;
import com.kyj.fmk.sec.model.member.CustomUserDetails;
import com.kyj.fmk.sec.model.res.SecurityResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        // TODO Auto-generated method stub
        String requestURI = request.getRequestURI();//자원을 가져옴
        return requestURI.equals("/api/v1/reissue"); //재발급시에는 필터를 수행하지않음
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, java.io.IOException {


        // 헤더에서 access키에 담긴 토큰을 꺼냄
        String accessToken = request.getHeader("Authorization");

        // 토큰이 없다면 다음 필터로 넘김
        if (accessToken == null) {

            filterChain.doFilter(request, response);

            return;
        }
        if (accessToken.startsWith("Bearer ")) {
            accessToken = accessToken.substring(7); // "Bearer " 이후의 실제 토큰만 추출
        }



        //토큰 검증
        boolean result = jwtUtil.validate(accessToken,response);

        if(!result){
            return;
        }


        // 토큰이 access인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(accessToken);

        if (!category.equals("access")) {
            //액세스토큰이 아닐시
            SecurityResponse.writeErrorRes(response, HttpStatus.UNAUTHORIZED,SecErrCode.SEC002);
        }



        String username = jwtUtil.getUsername(accessToken);//이메일
        String usrId= jwtUtil.getUsrId(accessToken);//고유번호
        String nickname=jwtUtil.getNickname(accessToken);//닉네임
        String sex = jwtUtil.getSex(accessToken);
        String birth = jwtUtil.getBirth(accessToken);
        String roles = jwtUtil.getRoles(accessToken);

        BaseMember members = new BaseMember();
        members.setUsername(username);
        members.setUsrId(usrId);
        members.setNickname(nickname);
        members.setSex(sex);
        members.setBirth(birth);
        members.setRoles(roles);

        CustomUserDetails customUserDetails = new CustomUserDetails(members);//ueserDetails에 dto객체 전달
        //일시적으로 세션에 담기위해 (SecurityContextHolder)
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}