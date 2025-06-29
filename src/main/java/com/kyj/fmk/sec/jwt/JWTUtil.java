package com.kyj.fmk.sec.jwt;

import com.kyj.fmk.sec.exception.SecErrCode;
import com.kyj.fmk.sec.model.res.SecurityResponse;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

import java.util.Date;

@Component
public final class JWTUtil {

    private final SecretKey secretKey;

    public JWTUtil(@Value("${spring.jwt.secret}") String secret) {

        //application.properties에 저장된 secretkey 암호 알고리즘 통해 생성사를 통해 secretkey 생성
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }




    public Boolean isExpired(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    public boolean validate(String token, HttpServletResponse response) {
        try {
            Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
        } catch (SignatureException e) {
            SecurityResponse.writeErrorRes(response, HttpStatus.UNAUTHORIZED,SecErrCode.SEC002);
        } catch (MalformedJwtException e) {
            SecurityResponse.writeErrorRes(response, HttpStatus.UNAUTHORIZED,SecErrCode.SEC002);
        } catch (ExpiredJwtException e) {
            SecurityResponse.writeErrorRes(response, HttpStatus.GONE,SecErrCode.SEC003);
        } catch (UnsupportedJwtException e) {
            SecurityResponse.writeErrorRes(response, HttpStatus.UNAUTHORIZED,SecErrCode.SEC002);
        } catch (IllegalArgumentException e) {
            SecurityResponse.writeErrorRes(response, HttpStatus.UNAUTHORIZED,SecErrCode.SEC002);
        } catch (Exception e){
            SecurityResponse.writeErrorRes(response, HttpStatus.UNAUTHORIZED,SecErrCode.SEC002);
        }

        return true;
    }



    public String getUsername(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    public String getCategory(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("category", String.class);
    }

    public String getNickname(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("nickname", String.class);
    }


    public String getUsrId(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("usrId", String.class);

    }

    public String getSex(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("sex", String.class);
    }


    public String getBirth(String token) {
        String dateStr = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("birth", String.class);
        return dateStr;
    }
    public String getRoles(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("roles", String.class);
    }


    //토큰을 만듬
    public String createJwt(String category, String username, String usrId, String nickname, String sex, String birth, String roles ,Long expiredMs) {

        return Jwts.builder()
                .claim("category", category) //refresh토큰인지 access 토큰인지
                .claim("username", username) //이름
                .claim("usrId", usrId)//아이디
                .claim("nickname", nickname)//닉네임
                .claim("sex", sex)
                .claim("birth", birth)
                .claim("roles",roles)
                .issuedAt(new Date(System.currentTimeMillis()))//만든날
                .expiration(new Date(System.currentTimeMillis() + expiredMs))//유효기간
                .signWith(secretKey)//시크릿키
                .compact();
    }

}
