package com.lobster.auth.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/test")
public class TestController {

    @GetMapping("/all")
    public String allAccess() {
        return "public content";
    }

    @GetMapping("/user")
    @PreAuthorize("hasAuthority('USER_ROLE') or hasAuthority('MODERATOR') or hasAuthority('ADMIN_ROLE')")
    public String userAccess() {
        return "User Content.";
    }
}
