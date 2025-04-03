package org.example.tripplanner.health;


import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("health-check")
public class HealthCheckController {
    @GetMapping
    public Object healthCheck() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        return auth.getCredentials();
    }
}
