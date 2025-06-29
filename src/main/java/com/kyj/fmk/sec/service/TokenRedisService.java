package com.kyj.fmk.sec.service;

import com.kyj.fmk.core.exception.custom.KyjSysException;
import com.kyj.fmk.core.model.dto.ResApiDTO;
import com.kyj.fmk.core.model.enm.ApiErrCode;
import com.kyj.fmk.sec.jwt.JWTUtil;
import com.kyj.fmk.core.util.CookieUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class TokenRedisService implements TokenService{
    private final RedisTemplate<String,Object> redisTemplate;
    private final JWTUtil jwtUtil;
    private final String REFRESH_TOKEN_KEY = "refresh:";

    @Override
    public void addRefresh(String key , String token) {
        TimeUnit timeUnit = TimeUnit.HOURS;
        long ttl = 24L * 7;  // 1주일 = 168시간
        String rediskey = REFRESH_TOKEN_KEY +key;
        System.out.println("token = " + token);
        redisTemplate.opsForValue().set(rediskey , token,ttl,timeUnit);
        redisTemplate.opsForValue().set(rediskey , token);
        redisTemplate.opsForValue().set("agida" , "agida");

        redisTemplate.opsForHash().put(rediskey,token,rediskey);

    }

    @Override
    public void deleteRefresh(String key , String token) {
        String rediskey = REFRESH_TOKEN_KEY+key;

        String findToken =(String)redisTemplate.opsForValue().get(rediskey);

        if(findToken.equals(token)){
            redisTemplate.delete(rediskey);
        }

    }

    @Override
    public boolean isExist(String key,String token) {
        String redisKey = REFRESH_TOKEN_KEY+key;
        String value = (String)redisTemplate.opsForValue().get(redisKey);

        if(value.equals(token)){
            return  true;
        }

        return false;
    }



    @Override
    //최종 refresh 토큰 발급 서비스
    public ResponseEntity<ResApiDTO<Void>> reissueToken(HttpServletRequest request, HttpServletResponse response) {


        String refresh = null;
        try {
            refresh=(String) CookieUtil.getCookie("refresh", request);

        } catch (Exception e) {
            // TODO: handle exception

            throw new KyjSysException(ApiErrCode.CM003);

        }

        if (refresh == null) {//만약 refresh가 없다면
            throw new KyjSysException(ApiErrCode.CM003);

        }

        try {
            jwtUtil.isExpired(refresh);// 유효기간 검증
        } catch (ExpiredJwtException e) {

          ResponseCookie responseCookie= CookieUtil.deleteCookie(refresh,"/");//refresh 쿠키제거메서드
            response.setHeader(HttpHeaders.SET_COOKIE,responseCookie.toString());
             String usrId = jwtUtil.getUsrId(refresh);

                redisTemplate.delete(REFRESH_TOKEN_KEY+ usrId);
                throw new KyjSysException(ApiErrCode.CM001,"만료된 세션입니다.");


        }


        String category = jwtUtil.getCategory(refresh);   // 토큰이 refresh인지 확인 (발급시 페이로드에 명시)

        if (!category.equals("refresh")) {//refresh 토큰이 아니면
                throw new KyjSysException(ApiErrCode.CM001,"토큰의 유형이 다릅니다.");
        }

        String chkUsrId=jwtUtil.getUsrId(refresh);


        Boolean isExist = isExist(chkUsrId,refresh); //DB에 저장되어 있는지 확인
        if (!isExist) {//없다면

           ResponseCookie responseCookie= CookieUtil.deleteCookie(refresh,"/");//refresh 쿠키제거메서드
            response.setHeader(HttpHeaders.SET_COOKIE,responseCookie.toString());

                throw new KyjSysException(ApiErrCode.CM001,"만료된 세션입니다.");
        }


        String usrId= jwtUtil.getUsrId(refresh);
        String nickname= jwtUtil.getNickname(refresh);
        String username = jwtUtil.getUsername(refresh);
        String sex = jwtUtil.getSex(refresh);
        String birth = jwtUtil.getBirth(refresh);
        String roles = jwtUtil.getRoles(refresh);

        //새로운 jwt 토큰 발급
        String nwAccess = jwtUtil.createJwt("access", username, usrId,nickname, sex, birth,roles,300000L);//엑세스 토큰
        String nwRefresh = jwtUtil.createJwt("refresh",  username, usrId,nickname, sex, birth,roles,86400000L); //리프레시 토큰


        deleteRefresh(usrId, refresh); //Refresh 토큰 저장 DB에 기존의 Refresh 토큰 삭제 후 새 Refresh 토큰 저장


        addRefresh(usrId,nwRefresh); //새토큰 저장


        //응답 설정
        response.setHeader("Authorization", "Bearer " + nwAccess);

        ResponseCookie responseCookie= CookieUtil.createCookie("refresh",nwRefresh,604800,"/");

        //성공시 응답
        response.setHeader(HttpHeaders.SET_COOKIE,responseCookie.toString());


        return ResponseEntity.ok(new ResApiDTO<Void>(null));
    }
}
