package com.example.springsecurity.enums;

public enum ErrorCase {
    NOT_FOUND("Such Comment not found`", 404),
    USER_NOT_FOUND("User not found", 404);

    private String message;
    private int code;

    ErrorCase(String message, int code) {
        this.message = message;
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public int getCode() {
        return code;
    }
}