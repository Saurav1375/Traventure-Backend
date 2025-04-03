package org.example.tripplanner.email;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.util.HashMap;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.mail.javamail.MimeMessageHelper.MULTIPART_MODE_MIXED;

@Service
@Slf4j
@RequiredArgsConstructor
public class EmailService {
    private final JavaMailSender mailSender;
    private final SpringTemplateEngine templateEngine;

    @Async
    public void sendConfirmationEmail(
            String to,
            String username,
            EmailTemplateName emailTemplate,
            String activationCode,
            String subject
    ) throws MessagingException {
        String templateName;
        if (emailTemplate == null) {
            templateName = "confirm-email";
        } else {
            templateName = emailTemplate.name();
        }
        MimeMessage mimeMessage = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(
                mimeMessage,
                MULTIPART_MODE_MIXED,
                UTF_8.name()
        );
        Map<String, Object> properties = new HashMap<>();
        properties.put("username", username);
        properties.put("activation_code", activationCode);

        Context context = new Context();
        context.setVariables(properties);

        helper.setFrom("sauravgupta1375@gmail.com");
        helper.setTo(to);
        helper.setSubject(subject);

        String template = templateEngine.process(templateName, context);

        helper.setText(template, true);

        mailSender.send(mimeMessage);
    }

    @Async
    public void sendResetPasswordEmail(String to) throws MessagingException {
        String resetLink = "http://localhost:8030/api/v1/reset?email=" + to;

        String message = "<html>"
                + "<body style='font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;'>"
                + "<div style='max-width: 500px; margin: auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.2);'>"
                + "<div class='logo-container'>"
                + "<img src='https://firebasestorage.googleapis.com/v0/b/getwel-8ce59.appspot.com/o/logo.png?alt=media&token=1224deb8-f5c1-47c0-b4df-2f70b92e0658' alt='Traventure' width='150' style='display: block; margin: auto;'>"
                + "</div>"
                + "<h2 style='color: #333; text-align: center;'>Reset Your Password</h2>"
                + "<p style='text-align: center;'>Hello,</p>"
                + "<p style='text-align: center;'>We received a request to reset your password. Click the button below to set a new password:</p>"
                + "<div style='text-align: center;'>"
                + "<a href='" + resetLink + "' style='display: inline-block; background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-size: 16px;'>Reset Password</a>"
                + "</div>"
                + "<p style='text-align: center;'>If you didn't request a password reset, please ignore this email.</p>"
                + "<p style='text-align: center;'>Thanks,<br>Traventure</p>"
                + "</div>"
                + "</body>"
                + "</html>";


        MimeMessage mailMessage = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(mailMessage, true, "UTF-8");

        helper.setTo(to);
        helper.setSubject("Password Reset Request");
        helper.setText(message, true); // 'true' enables HTML

        mailSender.send(mailMessage);
    }

    @Async
    public void sendAccountActivatedEmail(String to) throws MessagingException {
        String message = "<html>"
                + "<body style='font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;'>"
                + "<div style='max-width: 500px; margin: auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.2);'>"
                + "<div class='logo-container'>"
                + "<img src='https://firebasestorage.googleapis.com/v0/b/getwel-8ce59.appspot.com/o/logo.png?alt=media&token=1224deb8-f5c1-47c0-b4df-2f70b92e0658' alt='Traventure' width='150' style='display: block; margin: auto;'>"
                + "</div>"
                + "<h2 style='color: #28a745; text-align: center;'>🎉 Account Activated! 🎉</h2>"
                + "<p>Hello,</p>"
                + "<p>Welcome to Traventure. We're excited to let you know that your account has been successfully activated. You can now log in and start using our services.</p>"
                + "<div style='text-align: center; margin: 20px 0;'>"
                + "</div>"
                + "<p>If you did not request this activation, please contact our support team immediately.</p>"
                + "<p>Best Regards,<br>Traventure</p>"
                + "</div>"
                + "</body>"
                + "</html>";

        MimeMessage mailMessage = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(mailMessage, true, "UTF-8");

        helper.setTo(to);
        helper.setSubject("Your Account is Now Active! 🎉");
        helper.setText(message, true); // 'true' enables HTML formatting

        mailSender.send(mailMessage);
    }


}