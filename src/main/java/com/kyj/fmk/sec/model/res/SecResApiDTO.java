package com.kyj.fmk.sec.model.res;


import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
* 2025-05-29
* @author 김용준
* Restful Api에서 사용하는 성공응답 wrapper 클래스
*/
@Getter
public class SecResApiDTO<T> extends BaseSecResDTO {

    /**
    * 기본 생성자(응답 데이터가 없는)
    * 기본생성자 호출시 기본값을 세팅한다
    */
    public SecResApiDTO(){
        setDefaultVal();
    }
    /**
     * Rest api response
     *  응답데이터가 있는 생성자
     *  호출시 기본값을 세팅한다
     * @param <>
     *
     */
    public SecResApiDTO(T data){
        setDefaultVal();
        this.setData(data);
    }



    /**
     * Rest api response
     *  호출시 기본값을 세팅한다
     */
    private void setDefaultVal(){
        this.setStatus(HttpStatus.OK.value());
        this.setMsg("Success Request!");
    }
}
