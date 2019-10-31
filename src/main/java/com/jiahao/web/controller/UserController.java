package com.jiahao.web.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("users")
public class UserController {

    @RequestMapping("login")
    public String login(String username , String password){
        System.out.println("接受的参数:" + username + ":" + password);
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username,password);
        String path = null;
        try {
            subject.login(token);
            path = "home";
            System.out.println("认证成功!");
        } catch (AuthenticationException e) {
            path = "index";
            System.out.println("认证失败!");
        }
        return path;
    }

    /**
     * 注意点：此处如果没有权限，会抛出异常500
     * org.apache.shiro.authz.UnauthorizedException: Subject does not have role [XXX]
     * 解决方案：
     * 自定义异常：用户自定义异常，用户捕捉
     */
    @RequestMapping("f1")
    @RequiresRoles("admin")
    public void f1(){
        System.out.println("f1");
    }

    @RequestMapping("f2")
    @RequiresRoles("guest")
    public void f2(){
        System.out.println("f2");
    }
}
