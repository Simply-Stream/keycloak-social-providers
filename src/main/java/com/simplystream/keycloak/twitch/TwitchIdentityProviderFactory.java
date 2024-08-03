package com.simplystream.keycloak.twitch;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class TwitchIdentityProviderFactory extends AbstractIdentityProviderFactory<TwitchIdentityProvider> implements SocialIdentityProviderFactory<TwitchIdentityProvider> {
    public static final String PROVIDER_ID = "twitch";

    @Override
    public String getName() {
        return "Twitch (OIDC)";
    }

    @Override
    public TwitchIdentityProvider create(KeycloakSession keycloakSession, IdentityProviderModel identityProviderModel) {
        return new TwitchIdentityProvider(keycloakSession, new TwitchIdentityProviderConfig(identityProviderModel));
    }

    @Override
    public IdentityProviderModel createConfig() {
        return new TwitchIdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
