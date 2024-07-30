package com.simplystream.keycloak.twitch;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

public class TwitchIdentityProviderConfig extends OIDCIdentityProviderConfig {
    public TwitchIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
        super(identityProviderModel);
    }

    public TwitchIdentityProviderConfig() {
    }
}
