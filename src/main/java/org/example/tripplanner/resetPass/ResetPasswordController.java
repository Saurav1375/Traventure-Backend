package org.example.tripplanner.resetPass;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller  // Use @Controller, NOT @RestController
public class ResetPasswordController {

    @GetMapping("/reset")
    public String showResetPasswordPage(@RequestParam String email, Model model) {
        model.addAttribute("email", email);  // Pass email to Thymeleaf template
        return "reset-password";  // This should match reset-password.html in /templates/
    }
}

