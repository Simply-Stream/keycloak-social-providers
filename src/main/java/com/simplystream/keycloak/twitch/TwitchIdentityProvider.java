package com.simplystream.keycloak.twitch;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.MediaType;
import org.keycloak.vault.VaultStringSecret;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class TwitchIdentityProvider extends OIDCIdentityProvider implements SocialIdentityProvider<OIDCIdentityProviderConfig> {
    public static final String AUTH_URL = "https://id.twitch.tv/oauth2/authorize";
    public static final String TOKEN_URL = "https://id.twitch.tv/oauth2/token";
    public static final String USERINFO_URL = "https://id.twitch.tv/oauth2/userinfo";
    public static final String DEFAULT_SCOPES = "openid user:read:email";

    public TwitchIdentityProvider(KeycloakSession session, OIDCIdentityProviderConfig config) {
        super(session, config);

        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setUserInfoUrl(USERINFO_URL);
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPES;
    }

    @Override
    public BrokeredIdentityContext getFederatedIdentity(String response) {
        try {
            response = convertTwitchResponseToOidc(response);
        } catch (Exception ignored) {
        }

        return super.getFederatedIdentity(response);
    }

    @Override
    protected Response exchangeStoredToken(UriInfo uriInfo, EventBuilder event, ClientModel authorizedClient, UserSessionModel tokenUserSession, UserModel tokenSubject) {
        FederatedIdentityModel model = session.users().getFederatedIdentity(authorizedClient.getRealm(), tokenSubject, getConfig().getAlias());
        if (model == null || model.getToken() == null) {
            event.detail(Details.REASON, "requested_issuer is not linked");
            event.error(Errors.INVALID_TOKEN);
            return exchangeNotLinked(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
        }
        try (VaultStringSecret vaultStringSecret = session.vault().getStringSecret(getConfig().getClientSecret())) {
            String modelTokenString = model.getToken();
            AccessTokenResponse tokenResponse = JsonSerialization.readValue(modelTokenString, AccessTokenResponse.class);
            Integer exp = (Integer) tokenResponse.getOtherClaims().get(ACCESS_TOKEN_EXPIRATION);
            if (exp != null && exp < Time.currentTime()) {
                if (tokenResponse.getRefreshToken() == null) {
                    return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
                }
                String response = convertTwitchResponseToOidc(getRefreshTokenRequest(session, tokenResponse.getRefreshToken(),
                        getConfig().getClientId(), vaultStringSecret.get().orElse(getConfig().getClientSecret())).asString());
                if (response.contains("error")) {
                    logger.debugv("Error refreshing token, refresh token expiration?: {0}", response);
                    model.setToken(null);
                    session.users().updateFederatedIdentity(authorizedClient.getRealm(), tokenSubject, model);
                    event.detail(Details.REASON, "requested_issuer token expired");
                    event.error(Errors.INVALID_TOKEN);
                    return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
                }
                AccessTokenResponse newResponse = JsonSerialization.readValue(response, AccessTokenResponse.class);
                if (newResponse.getExpiresIn() > 0) {
                    int accessTokenExpiration = Time.currentTime() + (int) newResponse.getExpiresIn();
                    newResponse.getOtherClaims().put(ACCESS_TOKEN_EXPIRATION, accessTokenExpiration);
                }

                if (newResponse.getRefreshToken() == null && tokenResponse.getRefreshToken() != null) {
                    newResponse.setRefreshToken(tokenResponse.getRefreshToken());
                    newResponse.setRefreshExpiresIn(tokenResponse.getRefreshExpiresIn());
                }
                response = JsonSerialization.writeValueAsString(newResponse);

                String oldToken = tokenUserSession.getNote(FEDERATED_ACCESS_TOKEN);
                if (oldToken != null && oldToken.equals(tokenResponse.getToken())) {
                    int accessTokenExpiration = newResponse.getExpiresIn() > 0 ? Time.currentTime() + (int) newResponse.getExpiresIn() : 0;
                    tokenUserSession.setNote(FEDERATED_TOKEN_EXPIRATION, Long.toString(accessTokenExpiration));
                    tokenUserSession.setNote(FEDERATED_REFRESH_TOKEN, newResponse.getRefreshToken());
                    tokenUserSession.setNote(FEDERATED_ACCESS_TOKEN, newResponse.getToken());
                    tokenUserSession.setNote(FEDERATED_ID_TOKEN, newResponse.getIdToken());

                }
                model.setToken(response);
                session.users().updateFederatedIdentity(authorizedClient.getRealm(), tokenSubject, model);
                tokenResponse = newResponse;
            } else if (exp != null) {
                tokenResponse.setExpiresIn(exp - Time.currentTime());
            }
            tokenResponse.setIdToken(null);
            tokenResponse.setRefreshToken(null);
            tokenResponse.setRefreshExpiresIn(0);
            tokenResponse.getOtherClaims().clear();
            tokenResponse.getOtherClaims().put(OAuth2Constants.ISSUED_TOKEN_TYPE, OAuth2Constants.ACCESS_TOKEN_TYPE);
            tokenResponse.getOtherClaims().put(ACCOUNT_LINK_URL, getLinkingUrl(uriInfo, authorizedClient, tokenUserSession));
            event.success();
            return Response.ok(tokenResponse).type(jakarta.ws.rs.core.MediaType.APPLICATION_JSON_TYPE).build();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected Response exchangeSessionToken(UriInfo uriInfo, EventBuilder event, ClientModel authorizedClient, UserSessionModel tokenUserSession, UserModel tokenSubject) {
        String refreshToken = tokenUserSession.getNote(FEDERATED_REFRESH_TOKEN);
        String accessToken = tokenUserSession.getNote(FEDERATED_ACCESS_TOKEN);
        String idToken = tokenUserSession.getNote(FEDERATED_ID_TOKEN);

        if (accessToken == null) {
            event.detail(Details.REASON, "requested_issuer is not linked");
            event.error(Errors.INVALID_TOKEN);
            return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
        }
        try (VaultStringSecret vaultStringSecret = session.vault().getStringSecret(getConfig().getClientSecret())) {
            long expiration = Long.parseLong(tokenUserSession.getNote(FEDERATED_TOKEN_EXPIRATION));
            if (expiration == 0 || expiration > Time.currentTime()) {
                AccessTokenResponse tokenResponse = new AccessTokenResponse();
                tokenResponse.setExpiresIn(expiration);
                tokenResponse.setToken(accessToken);
                tokenResponse.setIdToken(null);
                tokenResponse.setRefreshToken(null);
                tokenResponse.setRefreshExpiresIn(0);
                tokenResponse.getOtherClaims().put(OAuth2Constants.ISSUED_TOKEN_TYPE, OAuth2Constants.ACCESS_TOKEN_TYPE);
                tokenResponse.getOtherClaims().put(ACCOUNT_LINK_URL, getLinkingUrl(uriInfo, authorizedClient, tokenUserSession));
                event.success();
                return Response.ok(tokenResponse).type(MediaType.APPLICATION_JSON_TYPE).build();
            }
            String response = convertTwitchResponseToOidc(getRefreshTokenRequest(session, refreshToken, getConfig().getClientId(), vaultStringSecret.get().orElse(getConfig().getClientSecret())).asString());
            if (response.contains("error")) {
                logger.debugv("Error refreshing token, refresh token expiration?: {0}", response);
                event.detail(Details.REASON, "requested_issuer token expired");
                event.error(Errors.INVALID_TOKEN);
                return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
            }
            FederatedIdentityModel model = session.users().getFederatedIdentity(authorizedClient.getRealm(), tokenSubject, getConfig().getAlias());
            AccessTokenResponse newResponse = JsonSerialization.readValue(response, AccessTokenResponse.class);
            long accessTokenExpiration = newResponse.getExpiresIn() > 0 ? Time.currentTime() + newResponse.getExpiresIn() : 0;
            tokenUserSession.setNote(FEDERATED_TOKEN_EXPIRATION, Long.toString(accessTokenExpiration));
            tokenUserSession.setNote(FEDERATED_REFRESH_TOKEN, newResponse.getRefreshToken());
            tokenUserSession.setNote(FEDERATED_ACCESS_TOKEN, newResponse.getToken());
            tokenUserSession.setNote(FEDERATED_ID_TOKEN, newResponse.getIdToken());
            newResponse.setIdToken(null);
            newResponse.setRefreshToken(null);
            newResponse.setRefreshExpiresIn(0);
            newResponse.getOtherClaims().clear();
            newResponse.getOtherClaims().put(OAuth2Constants.ISSUED_TOKEN_TYPE, OAuth2Constants.ACCESS_TOKEN_TYPE);
            newResponse.getOtherClaims().put(ACCOUNT_LINK_URL, getLinkingUrl(uriInfo, authorizedClient, tokenUserSession));
            model.setToken(response);
            event.success();
            return Response.ok(newResponse).type(MediaType.APPLICATION_JSON_TYPE).build();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private String convertTwitchResponseToOidc(String response) throws JsonProcessingException {
        mapper = new ObjectMapper();
        Map<String, Object> accessTokenResponseMap = mapper.readValue(response, new TypeReference<>() {
        });

        Object scopeObj = accessTokenResponseMap.get("scope");
        if (scopeObj instanceof List<?>) {
            String scope = ((List<?>) scopeObj).stream()
                    .map(Object::toString)
                    .collect(Collectors.joining(" "));

            accessTokenResponseMap.put("scope", scope);
            return mapper.writeValueAsString(accessTokenResponseMap);
        } else if (scopeObj instanceof String) {
            return mapper.writeValueAsString(accessTokenResponseMap);
        } else {
            throw new InvalidTokenResponseScopeException();
        }
    }
}
