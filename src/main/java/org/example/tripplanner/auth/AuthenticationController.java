package org.example.tripplanner.auth;


import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("auth")
@RequiredArgsConstructor
@Tag(name = "authentication")
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public ResponseEntity<?> register(
            @RequestBody @Valid RegistrationRequest request
    ) throws MessagingException {
        authenticationService.register(request);
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody @Valid AuthenticationRequest request
    ) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        authenticationService.refreshToken(request, response);
    }

    @GetMapping("/activate-account")
    public void confirm(
            @RequestParam String token,
            @RequestParam String email
    ) throws MessagingException {
        authenticationService.activateToken(token, email);
    }

    @GetMapping("/resend-code")
    public ResponseEntity<?> resendCode(
            @RequestParam("email") String userEmail
    ) {
        try {
            return ResponseEntity.ok(authenticationService.resendActivationCode(userEmail));
        } catch (MessagingException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }


    @GetMapping("/forget-password")
    public ResponseEntity<?> forgetPassword(
            @RequestParam("email") String email
    ) {
        try {
            authenticationService.forgetPassword(email);
            return ResponseEntity.ok().build();
        } catch (MessagingException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }

    }

    @GetMapping("/update-password")
    public ResponseEntity<String> updatePassword(
            @RequestParam("token") String token,
            @RequestParam("password") String password,
            @RequestParam("confirmPassword") String confirmPassword) {

        return ResponseEntity.ok(authenticationService.updatePassword(token, password, confirmPassword));
    }

}
