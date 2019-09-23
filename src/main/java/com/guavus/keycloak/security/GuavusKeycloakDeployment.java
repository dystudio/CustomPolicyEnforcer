package com.guavus.keycloak.security;

import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.representations.adapters.config.AdapterConfig;

public class GuavusKeycloakDeployment extends KeycloakDeploymentBuilder {
    @Override
    public KeycloakDeployment internalBuild(final AdapterConfig adapterConfig) {
        return super.internalBuild(adapterConfig);
    }
}
