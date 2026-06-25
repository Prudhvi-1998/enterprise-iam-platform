package com.iam.auth.dto;

import lombok.Data;
import java.util.Set;

@Data
public class UpdateUserRequest {

    private String email;
    private String password;
    private String status;
    private Set<String> roles;
}