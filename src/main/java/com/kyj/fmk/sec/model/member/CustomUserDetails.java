package com.kyj.fmk.sec.model.member;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class CustomUserDetails implements UserDetails {

    private BaseMember baseMember;

    public CustomUserDetails(BaseMember baseMember) {
        this.baseMember = baseMember;
    }

    public String getUsrNm(){
        return baseMember.getUsername();
    }

    public String getNickname(){
        return baseMember.getNickname();
    }

    public String getBirth(){
        return baseMember.getBirth();
    }

    public String getSex(){
        return baseMember.getSex();
    }
    @Override
    public String getPassword() {

        return baseMember.getPassWord();
    }

    @Override
    public String getUsername() {

        return baseMember.getUsrId();
    }

    @Override
    public boolean isAccountNonExpired() {

        return true;
    }

    @Override
    public boolean isAccountNonLocked() {

        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {

        return true;
    }

    @Override
    public boolean isEnabled() {

        return true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // TODO Auto-generated method stub
        List<String> list = Arrays.asList(baseMember.getRoles()
                .split(","));

        return list.stream()
                .map(String::trim) // 공백 제거 (안정성 ↑)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
