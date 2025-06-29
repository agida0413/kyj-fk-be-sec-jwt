package com.kyj.fmk.sec.model.member;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class BaseMember {
    private String usrId;
    private String passWord;
    private String username;
    private String roles;
    private String nickname;
    private String birth;
    private String sex;
}
