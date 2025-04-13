package org.example.tripplanner.handler;

import jakarta.mail.MessagingException;
import org.example.tripplanner.exception.BusinessException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Global exception handler that converts various exceptions into standardized API responses.
 * This ensures consistent error handling throughout the application.
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Handles BusinessException by converting it to a standardized ExceptionResponse.
     *
     * @param ex The BusinessException thrown
     * @param request The web request
     * @return ResponseEntity containing the exception details
     */
    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ExceptionResponse> handleBusinessException(BusinessException ex, WebRequest request) {
        ExceptionResponse response = ExceptionResponse.builder()
                .businessErrorCode(ex.getErrorCode().getCode())
                .businessErrorDescription(ex.getMessage())
                .error(ex.getErrorCode().name())
                .build();

        return new ResponseEntity<>(response, ex.getErrorCode().getHttpStatus());
    }

    /**
     * Handles validation exceptions from @Valid annotations.
     *
     * @param ex The validation exception
     * @param request The web request
     * @return ResponseEntity containing validation error details
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ExceptionResponse> handleValidationExceptions(
            MethodArgumentNotValidException ex,
            WebRequest request) {

        Map<String, String> errors = new HashMap<>();
        Set<String> validationMessages = new HashSet<>();

        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
            validationMessages.add(errorMessage);
        });

        ExceptionResponse response = ExceptionResponse.builder()
                .businessErrorCode(BusinessErrorCodes.BAD_REQUEST.getCode())
                .businessErrorDescription("Validation failed")
                .error(BusinessErrorCodes.BAD_REQUEST.name())
                .errors(errors)
                .validationErrors(validationMessages)
                .build();

        return new ResponseEntity<>(response, BusinessErrorCodes.BAD_REQUEST.getHttpStatus());
    }

    /**
     * Handles security-related exceptions and maps them to appropriate business error codes.
     */
    @ExceptionHandler({
            BadCredentialsException.class,
            DisabledException.class,
            LockedException.class,
            AccessDeniedException.class,
            UsernameNotFoundException.class
    })
    public ResponseEntity<ExceptionResponse> handleSecurityExceptions(Exception ex, WebRequest request) {
        BusinessErrorCodes errorCode = switch (ex) {
            case BadCredentialsException badCredentialsException -> BusinessErrorCodes.BAD_CREDENTIALS;
            case DisabledException disabledException -> BusinessErrorCodes.ACCOUNT_DISABLED;
            case LockedException lockedException -> BusinessErrorCodes.ACCOUNT_LOCKED;
            case AccessDeniedException accessDeniedException -> BusinessErrorCodes.UNAUTHORIZED_ACCESS;
            case UsernameNotFoundException usernameNotFoundException -> BusinessErrorCodes.USER_NOT_FOUND;
            case null, default -> BusinessErrorCodes.AUTHENTICATION_FAILED;
        };

        ExceptionResponse response = ExceptionResponse.builder()
                .businessErrorCode(errorCode.getCode())
                .businessErrorDescription(errorCode.getDescription())
                .error(errorCode.name())
                .build();

        return new ResponseEntity<>(response, errorCode.getHttpStatus());
    }

    /**
     * Handles email-related exceptions.
     */
    @ExceptionHandler(MessagingException.class)
    public ResponseEntity<ExceptionResponse> handleMessagingException(MessagingException ex, WebRequest request) {
        ExceptionResponse response = ExceptionResponse.builder()
                .businessErrorCode(BusinessErrorCodes.EMAIL_SENDING_FAILED.getCode())
                .businessErrorDescription("Failed to send email: " + ex.getMessage())
                .error(BusinessErrorCodes.EMAIL_SENDING_FAILED.name())
                .build();

        return new ResponseEntity<>(response, BusinessErrorCodes.EMAIL_SENDING_FAILED.getHttpStatus());
    }

    /**
     * Catch-all handler for any unhandled exceptions.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ExceptionResponse> handleGenericExceptions(Exception ex, WebRequest request) {
        ExceptionResponse response = ExceptionResponse.builder()
                .businessErrorCode(BusinessErrorCodes.UNKNOWN.getCode())
                .businessErrorDescription(BusinessErrorCodes.UNKNOWN.getDescription())
                .error(ex.getMessage())
                .build();

        return new ResponseEntity<>(response, BusinessErrorCodes.UNKNOWN.getHttpStatus());
    }
}