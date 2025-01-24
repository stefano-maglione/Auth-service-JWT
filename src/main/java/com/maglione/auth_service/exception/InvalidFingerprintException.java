package com.maglione.auth_service.exception;

public class InvalidFingerprintException extends RuntimeException {

    public InvalidFingerprintException(String message) {
        super(message);
    }

    public InvalidFingerprintException(String message, Throwable cause) {
        super(message, cause);
    }
}
