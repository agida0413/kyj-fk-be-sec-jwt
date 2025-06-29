package com.kyj.fmk.sec.model.res;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kyj.fmk.sec.exception.SecErrCode;
import com.kyj.fmk.sec.exception.SecErrHelper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import java.io.IOException;
/**
 * 2025-05-29
 * @author 김용준
 * 시큐리티 에서 사용하는 response객체를 write하는 클래스
 */
public final class SecurityResponse {

    /**
     * 성공응답객체
     * @param response
     * @throws IOException
     */
    public static void writeSuccessRes(HttpServletResponse response) throws IOException {

        ObjectMapper objectMapper = new ObjectMapper();

        SecResApiDTO<Void> responseDTO = new SecResApiDTO<>(null);

        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(responseDTO));

    }

    /**
     * 실패응답객체
     * @param response
     * @param secResApiDTO
     * @throws IOException
     */
    public static void writeErrorRes(HttpServletResponse response, HttpStatus httpStatus, SecErrCode secErrCode)  {
        ObjectMapper objectMapper = new ObjectMapper();

        String msg = SecErrHelper.determineErrMsg(secErrCode);
        SecResApiErrDTO secResApiDTO = new SecResApiErrDTO(msg,httpStatus.value());
        response.setStatus(httpStatus.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        try {
            response.getWriter().write(objectMapper.writeValueAsString(secResApiDTO));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        System.out.println(msg);
    }
}
