package com.simplystream.keycloak.discord;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class DiscordIdentityProviderFactory extends AbstractIdentityProviderFactory<DiscordIdentityProvider> implements SocialIdentityProviderFactory<DiscordIdentityProvider> {
    public static final String PROVIDER_ID = "discord_oidc";

    @Override
    public String getName() {
        return "Discord (OIDC)";
    }

    @Override
    public DiscordIdentityProvider create(KeycloakSession keycloakSession, IdentityProviderModel identityProviderModel) {
        return new DiscordIdentityProvider(keycloakSession, new DiscordIdentityProviderConfig(identityProviderModel));
    }

    @Override
    public IdentityProviderModel createConfig() {
        return new DiscordIdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
