package com.simplystream.keycloak.twitch;

public class InvalidTokenResponseScopeException extends RuntimeException {

    public InvalidTokenResponseScopeException() {
        super("Invalid \"scope\" provided in access token response.");
    }
}
