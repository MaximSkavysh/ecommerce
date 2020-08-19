package com.lobster.auth.payload.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@AllArgsConstructor
@Getter
@Setter
public class JwtResponse {

    private String token;
    private String type;
    private Long id;
    private String username;
    private String email;
    private List<String> roles;
}
