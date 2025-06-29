package com.kyj.fmk.sec.exception;

/**
 * 2025-05-30
 * @author 김용준
 * Restful Api에서 사용하는 에러응답객체에 대한 메시지 혹은 상태값 등을 결정해주는 Helper클래스이다.
 */
public class SecErrHelper {



    public static String determineErrMsg(SecErrCode secErrCode ){
        String code = "";
        String msg = "";

            code =  secErrCode.getCode();

            if(code.equals(SecErrCode.SEC001.getCode())){
                return secErrCode.getMsg();
            }else{
                msg = SecErrCode.of(code);

            }
        return msg;
    }

}
