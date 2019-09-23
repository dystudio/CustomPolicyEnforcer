package com.guavus.keycloak.security;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.log4j.Logger;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.authorization.PolicyEnforcer;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.util.SystemPropertiesJsonParserFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class GuavusAuthImpl {

    private static PolicyEnforcer customPolicyEnforcer = null;
    private static GuavusAuthImpl CustomAuthUtilInstance;
    private static Object CustomAuthUtilInstanceLock = new Object();
    private static Logger LOGGER = Logger.getLogger(GuavusAuthImpl.class);

    private GuavusAuthImpl() {
        getPolicyEnforcer();
    }

    public void authorize(HttpServletRequest request, HttpServletResponse response, Map<String, List<String>> permissionMap) {
        try {
            GuavusKeycloakPolicyEnforcer customPolicyEnforcer = GuavusKeycloakPolicyEnforcer.getGuavusPolicyEnforcerInstance(this.customPolicyEnforcer);
            Map<String, Resource> resolvedMap = resolvepermissionMap(permissionMap);
            customPolicyEnforcer.authorize(request, response, resolvedMap);
        } catch (Exception ex) {
            LOGGER.error("Error Occured while authorizing " + request.getRequestURI() + ", Error " + ex.getMessage());
        }
    }

    public void createResource(ResourceRepresentation resource) {
        if (!resource.getName().isEmpty()) {
            AuthzClient authzclient = getPolicyEnforcer().getClient();
            String token = getPolicyEnforcer().getClient().obtainAccessToken().getToken();
            resource = authzclient.protection(token).resource().create(resource);

        }
    }

    public void deleteResource(String resourceName) {
        AuthzClient authzclient = getPolicyEnforcer().getClient();
        String token = getPolicyEnforcer().getClient().obtainAccessToken().getToken();
        if (customPolicyEnforcer.getPaths().containsKey(resourceName)) {
            String resourceId = customPolicyEnforcer.getPaths().get(resourceName).getId();
            authzclient.protection(token).resource().delete(resourceId);
        }
    }

    public static GuavusAuthImpl getCustomAuthUtilInstance() {
        if (CustomAuthUtilInstance != null) {
            return CustomAuthUtilInstance;
        }
        synchronized (CustomAuthUtilInstanceLock) {
            if (CustomAuthUtilInstance == null) {
                CustomAuthUtilInstance = new GuavusAuthImpl();
            }
        }
        return CustomAuthUtilInstance;
    }

    private AdapterConfig loadAdapterConfig(InputStream is) {
        ObjectMapper mapper = new ObjectMapper(new SystemPropertiesJsonParserFactory());
        mapper.setSerializationInclusion(JsonInclude.Include.NON_DEFAULT);
        AdapterConfig adapterConfig;
        try {
            adapterConfig = mapper.readValue(is, AdapterConfig.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return adapterConfig;
    }


    private PolicyEnforcer getPolicyEnforcer() {
        try {
            InputStream configStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("keycloakConfig.json");
            AdapterConfig adapterConfig = loadAdapterConfig(configStream);
            KeycloakDeployment deploy = new GuavusKeycloakDeployment().internalBuild(adapterConfig);
            customPolicyEnforcer = deploy.getPolicyEnforcer();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return customPolicyEnforcer;
    }

    private Map<String, Resource> resolvepermissionMap(Map<String, List<String>> permissionMap) {
        Map<String, Resource> resolvedMap = new HashMap<>();
        try {
            for (Map.Entry<String, List<String>> resource : permissionMap.entrySet()) {
                if (customPolicyEnforcer.getPathMatcher().matches(resource.getKey()) != null) {
                    PolicyEnforcerConfig.PathConfig pathConfig = customPolicyEnforcer.getPathMatcher().matches(resource.getKey());
                    Resource res = new Resource(pathConfig.getName(), pathConfig.getPath(), resource.getValue());
                    resolvedMap.put(pathConfig.getId(), res);
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return resolvedMap;
    }

    class Resource {
        private String resourceName;

        public String getResourceName() {
            return resourceName;
        }

        public String getResourcePath() {
            return resourcePath;
        }

        public List<String> getScopes() {
            return scopes;
        }

        private String resourcePath;
        private List<String> scopes;

        Resource(String resourceName, String resourcePath, List<String> scopes) {
            this.resourceName = resourceName;
            this.resourcePath = resourcePath;
            this.scopes = scopes;
        }
    }

}
