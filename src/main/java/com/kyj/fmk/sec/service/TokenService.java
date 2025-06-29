package com.kyj.fmk.sec.service;

import com.kyj.fmk.core.model.dto.ResApiDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;

public interface TokenService {
    public void addRefresh(String key ,String token);
    public void deleteRefresh(String key,String token);
    public boolean isExist(String key,String token);
    public ResponseEntity<ResApiDTO<Void>> reissueToken(HttpServletRequest request, HttpServletResponse response);
}
