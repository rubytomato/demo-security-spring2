package com.example.demo.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping(path = "prelogin")
@Slf4j
public class PreLoginController {

    @GetMapping
    public String preLogin(HttpServletRequest request) {
        log.info(request.toString());
        DefaultCsrfToken token = (DefaultCsrfToken) request.getAttribute("_csrf");
        if (token == null) {
            throw new RuntimeException("could not get a token.");
        }
        return token.getToken();
    }

}
