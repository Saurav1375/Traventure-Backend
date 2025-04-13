package org.example.tripplanner.exception;

import lombok.Getter;
import org.example.tripplanner.handler.BusinessErrorCodes;

/**
 * Custom exception that carries business error code information.
 * This exception is used throughout the application to provide
 * consistent error handling and response formatting.
 */
public class BusinessException extends RuntimeException {

    @Getter
    private final BusinessErrorCodes errorCode;

    public BusinessException(BusinessErrorCodes errorCode) {
        super(errorCode.getDescription());
        this.errorCode = errorCode;
    }
    public BusinessException(BusinessErrorCodes errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }
}