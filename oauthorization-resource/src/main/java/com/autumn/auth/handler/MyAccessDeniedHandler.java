package com.autumn.auth.handler;

import com.autumn.auth.utils.ResponseResult;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

/**
 * @author autumn
 * @description 自定义AccessDeniedHandler
 * @date 2025年02月11日
 * @version: 1.0
 */
public class MyAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        if(request.getUserPrincipal() instanceof AbstractOAuth2TokenAuthenticationToken){
            ResponseResult.exceptionResponse(response,"权限不足");
        }else {
            ResponseResult.exceptionResponse(response,accessDeniedException);
        }
    }
}
