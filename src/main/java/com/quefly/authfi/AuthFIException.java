package com.quefly.authfi;

/** Exception thrown by AuthFI SDK operations. */
public class AuthFIException extends RuntimeException {
    private final int status;
    private final String code;

    public AuthFIException(String message, int status) {
        this(message, status, null);
    }

    public AuthFIException(String message, int status, String code) {
        super(message);
        this.status = status;
        this.code = code;
    }

    public AuthFIException(String message, Throwable cause) {
        super(message, cause);
        this.status = 500;
        this.code = null;
    }

    public int getStatus() { return status; }
    public String getCode() { return code; }
}
