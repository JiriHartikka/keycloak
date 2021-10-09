package org.keycloak.social.spotify;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class SpotifyIdentityProviderFactory extends AbstractIdentityProviderFactory<SpotifyIdentityProvider> implements SocialIdentityProviderFactory<SpotifyIdentityProvider> {

    public static final String PROVIDER_ID = "spotify";

    @Override
    public String getName() {
        return "Spotify";
    }

    @Override
    public SpotifyIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new SpotifyIdentityProvider(session, new OAuth2IdentityProviderConfig(model));
    }

    @Override
    public IdentityProviderModel createConfig() {
        return new OAuth2IdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
