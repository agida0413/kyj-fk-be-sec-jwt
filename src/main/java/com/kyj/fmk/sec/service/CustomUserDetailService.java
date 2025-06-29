package com.kyj.fmk.sec.service;

import com.kyj.fmk.sec.model.member.BaseMember;
import com.kyj.fmk.sec.model.member.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // TODO Auto-generated method stub

        BaseMember member  = new BaseMember();
        member.setUsername("agida0413");
        member.setPassWord("{noop}1234");
        member.setRoles("ROLE_USER");
        if(member!=null) {

            return new CustomUserDetails(member);
        }
        //없을경우 null 리턴
        throw new UsernameNotFoundException("사용자를 찾을 수 없습니다");
    }

}
