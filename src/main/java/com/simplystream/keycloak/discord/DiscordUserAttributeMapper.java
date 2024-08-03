package com.simplystream.keycloak.discord;

import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;

public class DiscordUserAttributeMapper extends AbstractJsonUserAttributeMapper {

    private static final String[] cp = new String[]{DiscordIdentityProviderFactory.PROVIDER_ID};

    @Override
    public String[] getCompatibleProviders() {
        return cp;
    }

    @Override
    public String getId() {
        return "discord-user-attribute-mapper";
    }

}
