package com.simplystream.keycloak.discord;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JsonSerialization;
import org.keycloak.vault.VaultStringSecret;

import java.io.IOException;

public class DiscordIdentityProvider extends OIDCIdentityProvider implements SocialIdentityProvider<OIDCIdentityProviderConfig> {
    public static final String AUTH_URL = "https://discord.com/oauth2/authorize";
    public static final String TOKEN_URL = "https://discord.com/api/oauth2/token";
    public static final String USERINFO_URL = "https://discord.com/api/users/@me";
    public static final String DEFAULT_SCOPES = "identify email";

    public DiscordIdentityProvider(KeycloakSession session, OIDCIdentityProviderConfig config) {
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
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode userInfo) {
        BrokeredIdentityContext user = new BrokeredIdentityContext(getJsonProperty(userInfo, "id"), getConfig());

        user.setUsername(getJsonProperty(userInfo, "username") + "#" + getJsonProperty(userInfo, "discriminator"));
        user.setEmail(getJsonProperty(userInfo, "email"));
        user.setIdp(this);

        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, userInfo, getConfig().getAlias());

        return user;
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
                logger.debugf("Refresh token: %s", tokenResponse.getRefreshToken());
                String response = getRefreshTokenRequest(session, tokenResponse.getRefreshToken(),
                        getConfig().getClientId(), vaultStringSecret.get().orElse(getConfig().getClientSecret())).asString();
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
            tokenResponse.getOtherClaims().clear();
            tokenResponse.getOtherClaims().put(OAuth2Constants.ISSUED_TOKEN_TYPE, OAuth2Constants.ACCESS_TOKEN_TYPE);
            tokenResponse.getOtherClaims().put(ACCOUNT_LINK_URL, getLinkingUrl(uriInfo, authorizedClient, tokenUserSession));
            event.success();
            return Response.ok(tokenResponse).type(MediaType.APPLICATION_JSON_TYPE).build();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected Response exchangeSessionToken(UriInfo uriInfo, EventBuilder event, ClientModel authorizedClient, UserSessionModel tokenUserSession, UserModel tokenSubject) {
        String refreshToken = tokenUserSession.getNote(FEDERATED_REFRESH_TOKEN);
        String accessToken = tokenUserSession.getNote(FEDERATED_ACCESS_TOKEN);

        if (accessToken == null) {
            event.detail(Details.REASON, "requested_issuer is not linked");
            event.error(Errors.INVALID_TOKEN);
            return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
        }
        try (VaultStringSecret vaultStringSecret = session.vault().getStringSecret(getConfig().getClientSecret())) {
            long expiration = Long.parseLong(tokenUserSession.getNote(FEDERATED_TOKEN_EXPIRATION));
            logger.debug("Access token not expired");
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
            logger.debug("Refreshing Token");
            String response = getRefreshTokenRequest(session, refreshToken, getConfig().getClientId(), vaultStringSecret.get().orElse(getConfig().getClientSecret())).asString();
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

    @Override
    protected BrokeredIdentityContext extractIdentity(AccessTokenResponse tokenResponse, String accessToken, JsonWebToken idToken) throws IOException {
        String id = idToken.getSubject();
        BrokeredIdentityContext identity = new BrokeredIdentityContext(id, getConfig());
        String preferredUsername = "";
        String email = "";

        if (!getConfig().isDisableUserInfoService()) {
            String userInfoUrl = getUserInfoUrl();
            if (userInfoUrl != null && !userInfoUrl.isEmpty()) {

                if (accessToken != null) {
                    SimpleHttp.Response response = executeRequest(userInfoUrl, SimpleHttp.doGet(userInfoUrl, session).header("Authorization", "Bearer " + accessToken));
                    String contentType = response.getFirstHeader(HttpHeaders.CONTENT_TYPE);
                    MediaType contentMediaType;
                    try {
                        contentMediaType = MediaType.valueOf(contentType);
                    } catch (IllegalArgumentException ex) {
                        contentMediaType = null;
                    }
                    if (contentMediaType == null || contentMediaType.isWildcardSubtype() || contentMediaType.isWildcardType()) {
                        throw new RuntimeException("Unsupported content-type [" + contentType + "] in response from [" + userInfoUrl + "].");
                    }
                    JsonNode userInfo;

                    if (MediaType.APPLICATION_JSON_TYPE.isCompatible(contentMediaType)) {
                        userInfo = response.asJson();
                    } else {
                        throw new RuntimeException("Unsupported content-type [" + contentType + "] in response from [" + userInfoUrl + "].");
                    }

                    id = getJsonProperty(userInfo, "id");
                    preferredUsername = getJsonProperty(userInfo, "username") + "#" + getJsonProperty(userInfo, "discriminator");
                    email = getJsonProperty(userInfo, "email");
                    AbstractJsonUserAttributeMapper.storeUserProfileForMapper(identity, userInfo, getConfig().getAlias());
                }
            }
        }

        identity.getContextData().put(VALIDATED_ID_TOKEN, idToken);
        identity.setId(id);
        identity.setEmail(email);
        identity.setBrokerUserId(getConfig().getAlias() + "." + id);
        identity.setUsername(preferredUsername);
        if (tokenResponse != null && tokenResponse.getSessionState() != null) {
            identity.setBrokerSessionId(getConfig().getAlias() + "." + tokenResponse.getSessionState());
        }
        if (tokenResponse != null) identity.getContextData().put(FEDERATED_ACCESS_TOKEN_RESPONSE, tokenResponse);
        if (tokenResponse != null) processAccessTokenResponse(identity, tokenResponse);

        return identity;
    }

    private SimpleHttp.Response executeRequest(String url, SimpleHttp request) throws IOException {
        SimpleHttp.Response response = request.asResponse();
        if (response.getStatus() != 200) {
            String msg = "failed to invoke url [" + url + "]";
            try {
                String tmp = response.asString();
                if (tmp != null) msg = tmp;

            } catch (IOException ignored) {
            }
            throw new IdentityBrokerException("Failed to invoke url [" + url + "]: " + msg);
        }
        return response;
    }
}
