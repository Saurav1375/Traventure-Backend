package org.example.tripplanner.handler;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.*;

/**
 * Enumeration of business error codes used throughout the application.
 * Each error code has an associated HTTP status code and description.
 *
 * Error code groups:
 * 0-99: General errors
 * 100-199: Authentication errors
 * 200-299: Validation errors
 * 300-399: Account management errors
 * 400-499: Email and communication errors
 * 500-599: Token and session errors
 * 600-699: Permission and access errors
 * 900-999: System and unexpected errors
 */
public enum BusinessErrorCodes {
    NO_CODE(0, NOT_IMPLEMENTED, "Unspecified error occurred"),

    // Authentication errors (100-199)
    AUTHENTICATION_FAILED(100, UNAUTHORIZED, "Authentication failed"),
    BAD_CREDENTIALS(101, UNAUTHORIZED, "The email or password provided is incorrect"),

    // Account management errors (300-399)
    INCORRECT_CURRENT_PASSWORD(300, HttpStatus.BAD_REQUEST, "The current password entered is incorrect"),
    NEW_PASSWORD_DOES_NOT_MATCH(301, HttpStatus.BAD_REQUEST, "New password and confirmation do not match"),
    ACCOUNT_LOCKED(302, FORBIDDEN, "This account is temporarily locked due to multiple failed login attempts"),
    ACCOUNT_DISABLED(303, FORBIDDEN, "This account has been disabled. Please contact support"),

    USER_NOT_FOUND(305, NOT_FOUND, "No user found with the provided credentials"),
    EMAIL_ALREADY_REGISTERED(306, CONFLICT, "An account with this email already exists"),
    ACCOUNT_NOT_VERIFIED(307, UNAUTHORIZED, "Email address not verified. Please check your inbox"),
    ACCOUNT_ALREADY_ACTIVATED(308, HttpStatus.BAD_REQUEST, "This account is already activated"),

    // Token and session errors (500-599)
    INVALID_TOKEN(500, UNAUTHORIZED, "Authentication token is invalid"),
    EXPIRED_TOKEN(501, UNAUTHORIZED, "Your session has expired. Please log in again"),
    MISSING_TOKEN(502, HttpStatus.BAD_REQUEST, "Authentication token is required"),

    // Validation errors (200-299)
    WEAK_PASSWORD(200, HttpStatus.BAD_REQUEST,
            "Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one digit, and one special character (e.g., @$!%*?&)"),
    INVALID_EMAIL_FORMAT(201, HttpStatus.BAD_REQUEST, "The email format is invalid"),

    // Rate limiting and security (600-699)
    TOO_MANY_REQUESTS(600, HttpStatus.TOO_MANY_REQUESTS, "Too many attempts. Please try again later"),
    UNAUTHORIZED_ACCESS(601, FORBIDDEN, "You do not have permission to perform this action"),

    // Email and communication errors (400-499)
    EMAIL_SENDING_FAILED(400, INTERNAL_SERVER_ERROR, "Failed to send email"),

    // System and configuration errors (700-799)
    ROLE_NOT_FOUND(700, INTERNAL_SERVER_ERROR, "System role not found"),

    // Unknown and other errors (900-999)
    UNKNOWN(999, INTERNAL_SERVER_ERROR, "An unknown error occurred"),
    BAD_REQUEST(102, HttpStatus.BAD_REQUEST , "Bad request" ),;

    @Getter
    private final int code;
    @Getter
    private final String description;
    @Getter
    private final HttpStatus httpStatus;

    BusinessErrorCodes(int code, HttpStatus status, String description) {
        this.code = code;
        this.description = description;
        this.httpStatus = status;
    }
}