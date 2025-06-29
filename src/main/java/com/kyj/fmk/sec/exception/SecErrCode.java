package com.kyj.fmk.sec.exception;

import lombok.Getter;

import java.util.HashMap;
import java.util.Map;
@Getter
public enum SecErrCode {

    SEC001("SEC001","기본응답메시지 {0}"),
    SEC002("SEC002","잘못된 토큰형식입니다."),
    SEC003("SEC003","토큰의 유효기간이 만료되었습니다."),
    SEC004("SEC004","아이디와 비밀번호는 필수입력 항목입니다."),
    SEC005("SEC005","로그인정보가 일치하지 않습니다."),
    SEC006("SEC006","서버내부 오류입니다."),
    SEC007("SEC007","세션이 만료되었습니다.");


    private final String code;
    private final String msg;

    /**
     * 에러코드 생성자
     * @param code
     * @param msg
     */
    SecErrCode(String code, String msg) {
        this.code = code;
        this.msg = msg;
    }

    /**
     * 정적 맵 초기화 (O(1) 조회용)
     */
    private static final Map<String, SecErrCode> CODE_MAP = new HashMap<>();

    static {
        for (SecErrCode errCode : values()) {
            CODE_MAP.put(errCode.code, errCode);
        }
    }

    /**
     * O1복잡도로 정적 맵에서 알맞은 메시지를 가져온다.
     * @param code
     * @return ApiErrCode
     */
    public static String of(String code) {
        return CODE_MAP.get(code).getMsg();
    }
}
