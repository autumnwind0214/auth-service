package com.autumn.auth.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author autumn
 * @description 由于接口资源地址没有在Spring Security配置中放开，因此三个接口访问都需要传入accessToken。其中，messages1接口的要求只需传入accessToken，messages2接口要求传入accessToken和拥有profile权限，messages3接口要求传入accessToken和拥有Message权限
 * 而message4接口是新增的一个，试试用户的这个权限访问结果
 * @date 2025年02月11日
 * @version: 1.0
 */
@RestController
public class MessagesController {

    @GetMapping("/messages1")
    public String getMessages1() {
        return " hello Message 1";
    }

    @GetMapping("/messages2")
    @PreAuthorize("hasAuthority('SCOPE_profile')")
    public String getMessages2() {
        return " hello Message 2";
    }

    @GetMapping("/messages3")
    @PreAuthorize("hasAuthority('SCOPE_Message')")
    public String getMessages3() {
        return " hello Message 3";
    }

    @GetMapping("/messages4")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public String getMessages4() {
        return " hello Message 4";
    }
}
