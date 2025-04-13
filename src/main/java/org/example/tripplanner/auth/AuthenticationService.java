package org.example.tripplanner.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.example.tripplanner.email.EmailService;
import org.example.tripplanner.email.EmailTemplateName;
import org.example.tripplanner.exception.BusinessException;
import org.example.tripplanner.handler.BusinessErrorCodes;
import org.example.tripplanner.role.RoleRepository;
import org.example.tripplanner.security.JwtService;
import org.example.tripplanner.user.Token;
import org.example.tripplanner.user.TokenRepository;
import org.example.tripplanner.user.User;
import org.example.tripplanner.user.UserRepository;
import org.springframework.security.authentication.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Pattern;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

/**
 * Service class that handles all authentication-related operations including:
 * - User registration
 * - Authentication
 * - Account activation
 * - Password recovery
 * - Token refresh
 */
@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenRepository tokenRepository;
    private final EmailService emailService;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$");

    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$"
    );

    /**
     * Registers a new user in the system.
     * The user will be created but disabled until they activate their account.
     *
     * @param request The registration details including firstname, lastname, email, and password
     * @throws MessagingException If there is an error sending the activation email
     * @throws BusinessException  If the email is already registered
     */
    public void register(RegistrationRequest request) throws MessagingException {
        // Check if email already exists
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new BusinessException(BusinessErrorCodes.EMAIL_ALREADY_REGISTERED);
        }
        if (!EMAIL_PATTERN.matcher(request.getEmail()).matches()) {
            throw new BusinessException(BusinessErrorCodes.INVALID_EMAIL_FORMAT);
        }

        // Validate password strength
        if (!PASSWORD_PATTERN.matcher(request.getPassword()).matches()) {
            throw new BusinessException(BusinessErrorCodes.WEAK_PASSWORD);
        }

        var userRole = roleRepository.findByName("USER").orElseThrow(
                () -> new BusinessException(BusinessErrorCodes.ROLE_NOT_FOUND, "ROLE USER was not initialized")
        );

        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(List.of(userRole))
                .accountLocked(false)
                .enabled(false)
                .build();
        userRepository.save(user);
        sendValidationEmail(user);
    }

    /**
     * Sends a validation email to the user with an activation code.
     *
     * @param user The user to send the validation email to
     * @throws MessagingException If there is an error sending the email
     */
    private void sendValidationEmail(User user) throws MessagingException {
        var newToken = generateAndSaveActivationToken(user);
        try {
            emailService.sendConfirmationEmail(
                    user.getEmail(),
                    user.getFullName(),
                    EmailTemplateName.ACTIVATE_ACCOUNT,
                    newToken,
                    "Account activation"
            );
        } catch (Exception e) {
            throw new BusinessException(BusinessErrorCodes.EMAIL_SENDING_FAILED, "Failed to send activation email");
        }
    }

    /**
     * Generates and saves an activation token for a user.
     *
     * @param user The user to generate the token for
     * @return The generated token string
     */
    private String generateAndSaveActivationToken(User user) {
        //generate token
        String generatedToken = generateActivationCode(4);
        var token = Token.builder()
                .token(generatedToken)
                .createdAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusMinutes(15))
                .user(user)
                .build();
        tokenRepository.save(token);
        return generatedToken;
    }

    /**
     * Resends an activation code to a user who hasn't activated their account yet.
     *
     * @param userEmail The email of the user to resend the activation code to
     * @return A message indicating the result of the operation
     * @throws MessagingException If there is an error sending the email
     * @throws BusinessException  If the user is not found or account is already activated
     */
    public String resendActivationCode(String userEmail) throws MessagingException {
        var user = userRepository.findByEmail(userEmail).orElseThrow(
                () -> new BusinessException(BusinessErrorCodes.USER_NOT_FOUND)
        );
        if (user.isEnabled()) {
            throw new BusinessException(BusinessErrorCodes.ACCOUNT_ALREADY_ACTIVATED);
        }
        tokenRepository.findByUser(user).ifPresent(tokenRepository::deleteAll);
        sendValidationEmail(user);
        return "Activation code sent";
    }

    /**
     * Generates a secure random activation code of specified length.
     *
     * @param length The length of the activation code
     * @return The generated activation code
     */
    private String generateActivationCode(int length) {
        String characters = "0123456789";
        StringBuilder codeBuilder = new StringBuilder();
        SecureRandom secureRandom = new SecureRandom();
        for (int i = 0; i < length; i++) {
            int randomIndex = secureRandom.nextInt(characters.length());
            codeBuilder.append(characters.charAt(randomIndex));
        }
        return codeBuilder.toString();
    }

    /**
     * Authenticates a user with email and password.
     *
     * @param request The authentication request containing email and password
     * @return Authentication response with access and refresh tokens
     * @throws BusinessException If authentication fails for any reason
     */
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        try {
            var auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );


            var claims = new HashMap<String, Object>();
            var user = (User) auth.getPrincipal();
            claims.put("fullName", user.getFullName());
            var jwtToken = jwtService.generateToken(claims, user);
            var refreshToken = jwtService.generateRefreshToken(claims, user);

            // Check if user's email is verified

            return AuthenticationResponse.builder()
                    .accessToken(jwtToken)
                    .refreshToken(refreshToken)
                    .build();

        } catch (BadCredentialsException e) {
            throw new BusinessException(BusinessErrorCodes.BAD_CREDENTIALS);
        } catch (DisabledException e) {
            throw new BusinessException(BusinessErrorCodes.ACCOUNT_NOT_VERIFIED);
        } catch (LockedException e) {
            throw new BusinessException(BusinessErrorCodes.ACCOUNT_LOCKED);
        } catch (Exception e) {
            throw new BusinessException(BusinessErrorCodes.AUTHENTICATION_FAILED, "Authentication failed: " + e.getMessage());
        }
    }

    /**
     * Activates a user account using the provided token.
     *
     * @param token The activation token
     * @throws MessagingException If there is an error sending the confirmation email
     * @throws BusinessException  If the token is invalid, expired, or user not found
     */
    public void activateToken(String token) throws MessagingException {
        Token savedToken = tokenRepository.findByToken(token).orElseThrow(
                () -> new BusinessException(BusinessErrorCodes.INVALID_TOKEN, "Token does not exist")
        );
        if (LocalDateTime.now().isAfter(savedToken.getExpiresAt())) {
            sendValidationEmail(savedToken.getUser());
            throw new BusinessException(BusinessErrorCodes.EXPIRED_TOKEN, "Activation token has expired. A new activation token has been sent to the user.");
        }
        var user = userRepository.findById(savedToken.getUser().getId()).orElseThrow(
                () -> new BusinessException(BusinessErrorCodes.USER_NOT_FOUND)
        );
        user.setEnabled(true);
        userRepository.save(user);
        savedToken.setValidatedAt(LocalDateTime.now());
        try {
            emailService.sendAccountActivatedEmail(user.getEmail());
        } catch (Exception e) {
            // We still proceed with activation even if the confirmation email fails
            throw new BusinessException(BusinessErrorCodes.EMAIL_SENDING_FAILED, "Account activated but failed to send confirmation email");
        }
        tokenRepository.save(savedToken);
    }

    /**
     * Initiates the password reset process for a user.
     *
     * @param email The email of the user who wants to reset their password
     * @throws MessagingException If there is an error sending the reset email
     * @throws BusinessException  If the user does not exist
     */
    public void forgetPassword(String email) throws MessagingException {
        val user = userRepository.findByEmail(email).orElseThrow(
                () -> new BusinessException(BusinessErrorCodes.USER_NOT_FOUND)
        );
        var newValidToken = generateAndSaveActivationToken(user);

        try {
            emailService.sendResetPasswordEmail(email, newValidToken);
        } catch (Exception e) {
            throw new BusinessException(BusinessErrorCodes.EMAIL_SENDING_FAILED, "Failed to send password reset email");
        }
    }

    /**
     * Refreshes the JWT access token using a valid refresh token.
     *
     * @param request  HTTP request containing the refresh token in the Authorization header
     * @param response HTTP response to write the new tokens to
     * @throws IOException       If there is an error writing to the response
     * @throws BusinessException If the token is invalid or missing
     */
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader(AUTHORIZATION);
        final String refreshToken;
        final String userEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new BusinessException(BusinessErrorCodes.MISSING_TOKEN);
        }
        refreshToken = authHeader.substring(7);

        try {
            userEmail = jwtService.extractUsername(refreshToken);
        } catch (Exception e) {
            throw new BusinessException(BusinessErrorCodes.INVALID_TOKEN);
        }

        if (userEmail != null) {
            var user = userRepository.findByEmail(userEmail).orElseThrow(
                    () -> new BusinessException(BusinessErrorCodes.USER_NOT_FOUND)
            );
            if (jwtService.isTokenValid(refreshToken, user)) {
                var claims = new HashMap<String, Object>();
                claims.put("fullName", user.getFullName());
                var jwtToken = jwtService.generateToken(claims, user);
                var authResponse = AuthenticationResponse.builder()
                        .accessToken(jwtToken)
                        .refreshToken(refreshToken)
                        .build();

                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            } else {
                throw new BusinessException(BusinessErrorCodes.EXPIRED_TOKEN);
            }
        } else {
            throw new BusinessException(BusinessErrorCodes.INVALID_TOKEN);
        }
    }

    /**
     * Updates a user's password after validation of the reset token.
     *
     * @param token           The reset token
     * @param password        The new password
     * @param confirmPassword Password confirmation to ensure they match
     * @return A message indicating the result of the operation
     * @throws BusinessException If token is invalid, expired, or passwords don't match
     */
    public String updatePassword(String token, String password, String confirmPassword) {
        val savedTokenInDb = tokenRepository.findByToken(token).orElseThrow(
                () -> new BusinessException(BusinessErrorCodes.INVALID_TOKEN, "Token does not exist")
        );

        // Validate password strength
        if (!PASSWORD_PATTERN.matcher(password).matches()) {
            throw new BusinessException(BusinessErrorCodes.WEAK_PASSWORD);
        }
        if (LocalDateTime.now().isAfter(savedTokenInDb.getExpiresAt())) {
            throw new BusinessException(BusinessErrorCodes.EXPIRED_TOKEN, "Session has expired.");
        }
        var user = userRepository.findById(savedTokenInDb.getUser().getId()).orElseThrow(
                () -> new BusinessException(BusinessErrorCodes.USER_NOT_FOUND)
        );
        if (!password.equals(confirmPassword)) {
            throw new BusinessException(BusinessErrorCodes.NEW_PASSWORD_DOES_NOT_MATCH);
        }

        user.setPassword(passwordEncoder.encode(password));
        userRepository.save(user);
        return "Password successfully updated";
    }
}