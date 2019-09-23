package com.guavus.keycloak.security;

import org.keycloak.representations.idm.authorization.ResourceRepresentation;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Map;

public interface GuavusAuthInterface {
    void authorize(HttpServletRequest request, HttpServletResponse response, Map<String, List<String>> permissionMap);

    void createResource(ResourceRepresentation resource);

    void deleteResource(String resourceName);
}
