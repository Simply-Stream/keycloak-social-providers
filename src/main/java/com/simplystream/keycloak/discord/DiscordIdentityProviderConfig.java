package com.simplystream.keycloak.discord;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

public class DiscordIdentityProviderConfig extends OIDCIdentityProviderConfig {
    public DiscordIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
        super(identityProviderModel);
    }

    public DiscordIdentityProviderConfig() {
    }
}
