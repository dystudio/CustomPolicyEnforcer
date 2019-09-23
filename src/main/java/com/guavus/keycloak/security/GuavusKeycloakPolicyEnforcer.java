package com.guavus.keycloak.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.apache.log4j.Logger;
import org.keycloak.AuthorizationContext;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.OIDCHttpFacade;
import org.keycloak.adapters.authorization.KeycloakAdapterPolicyEnforcer;
import org.keycloak.adapters.authorization.PolicyEnforcer;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.springsecurity.facade.SimpleHttpFacade;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.ClientAuthorizationContext;
import org.keycloak.authorization.client.resource.PermissionResource;
import org.keycloak.authorization.client.resource.ProtectionResource;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.representations.idm.authorization.PermissionRequest;
import com.guavus.keycloak.security.GuavusAuthImpl.Resource;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

public class GuavusKeycloakPolicyEnforcer extends KeycloakAdapterPolicyEnforcer {
    private static Logger LOGGER = Logger.getLogger(GuavusKeycloakPolicyEnforcer.class);
    private static DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
    private PolicyEnforcer customPolicyEnforcer;
    private static Object GuavusPolicyEnforcerInstanceLock = new Object();
    private static GuavusKeycloakPolicyEnforcer GuavusPolicyEnforcerInstance = null;

    private GuavusKeycloakPolicyEnforcer(PolicyEnforcer policyEnforcer) {
        super(policyEnforcer);
        this.customPolicyEnforcer = policyEnforcer;
    }

    public static GuavusKeycloakPolicyEnforcer getGuavusPolicyEnforcerInstance(PolicyEnforcer customPolicyEnforcer) {
        if (GuavusPolicyEnforcerInstance != null) {
            return GuavusPolicyEnforcerInstance;
        }
        synchronized (GuavusPolicyEnforcerInstanceLock) {
            if (GuavusPolicyEnforcerInstance == null) {
                GuavusPolicyEnforcerInstance = new GuavusKeycloakPolicyEnforcer(customPolicyEnforcer);
            }
        }
        return GuavusPolicyEnforcerInstance;
    }

    protected boolean challenge(Map<String, GuavusAuthImpl.Resource> permissionMap, OIDCHttpFacade httpFacade) {
        HttpFacade.Response response = httpFacade.getResponse();
        AuthzClient authzClient = getAuthzClient();
        String ticket = getPermissionTicket(permissionMap, authzClient, httpFacade);
        if (ticket != null) {
            response.setStatus(401);
            response.setHeader("WWW-Authenticate", new StringBuilder("UMA realm=\"").append(authzClient.getConfiguration().getRealm()).append("\"").append(",as_uri=\"")
                    .append(authzClient.getServerConfiguration().getIssuer()).append("\"").append(",ticket=\"").append(ticket).append("\"").toString());
        } else {
            response.setStatus(403);
        }
        return true;
    }

    public AuthorizationContext authorize(HttpServletRequest request, HttpServletResponse response, Map<String, GuavusAuthImpl.Resource> permissionMap) {
        HttpFacade facade = new SimpleHttpFacade(request, response);
        OIDCHttpFacade httpFacade = (OIDCHttpFacade) facade;
        KeycloakSecurityContext securityContext = (KeycloakSecurityContext) request.getAttribute(KeycloakSecurityContext.class.getName());
        AuditLogs auditLogs = new AuditLogs();
        auditLogs.setClientIP(getClientIpAddress(request));
        auditLogs.setURI(request.getRequestURI());
        if (securityContext == null) {
            if (!isDefaultAccessDeniedUri(httpFacade.getRequest())) {
                if (permissionMap != null) {
                    challenge(permissionMap, httpFacade);
                } else {
                    handleAccessDenied(httpFacade);
                }
            }
            auditLogs.setStatus(response.getStatus());
            writeLogs(auditLogs, permissionMap);
            return createEmptyAuthorizationContext(false);
        }

        AccessToken accessToken = securityContext.getToken();
        if (accessToken != null) {
            String UserId = accessToken.getOtherClaims().get("user_id").toString();
            String Username = accessToken.getOtherClaims().get("user_name").toString();
            if (UserId != null) auditLogs.setUserID(UserId);
            if (Username != null) auditLogs.setUsername(Username);
            if (isAuthorized(permissionMap, accessToken, httpFacade, null)) {
                try {
                    auditLogs.setStatus(response.getStatus());
                    writeLogs(auditLogs, permissionMap);
                    return createAuthorizationContext(accessToken, null);
                } catch (Exception e) {
                    throw new RuntimeException("Error processing path [" + httpFacade.getRequest().getURI() + "].", e);
                }
            }

            if (!challenge(permissionMap, httpFacade)) {
//                if (LOGGER.isDebugEnabled()) {
//                    LOGGER.debugf("Challenge not sent, sending default forbidden response. Path [%s]", request.getURI());
//                }
                handleAccessDenied(httpFacade);
            }
        }

        return createEmptyAuthorizationContext(false);
    }

    private boolean isDefaultAccessDeniedUri(HttpFacade.Request request) {
        String accessDeniedPath = getEnforcerConfig().getOnDenyRedirectTo();
        return accessDeniedPath != null && request.getURI().contains(accessDeniedPath);
    }

    private AuthorizationContext createEmptyAuthorizationContext(final boolean granted) {
        return new ClientAuthorizationContext(getAuthzClient()) {
            @Override
            public boolean hasPermission(String resourceName, String scopeName) {
                return granted;
            }

            @Override
            public boolean hasResourcePermission(String resourceName) {
                return granted;
            }

            @Override
            public boolean hasScopePermission(String scopeName) {
                return granted;
            }

            @Override
            public List<Permission> getPermissions() {
                return Collections.EMPTY_LIST;
            }

            @Override
            public boolean isGranted() {
                return granted;
            }
        };
    }

    private AuthorizationContext createAuthorizationContext(AccessToken
                                                                    accessToken, PolicyEnforcerConfig.PathConfig pathConfig) {
        return new ClientAuthorizationContext(accessToken, pathConfig, getAuthzClient());
    }

    private String getPermissionTicket(Map<String, GuavusAuthImpl.Resource> permissionMap, AuthzClient
            authzClient, OIDCHttpFacade httpFacade) {
        if (customPolicyEnforcer.getEnforcerConfig().getUserManagedAccess() != null) {
            ProtectionResource protection = authzClient.protection();
            PermissionResource permission = protection.permission();
            List<PermissionRequest> permissionRequests = new ArrayList<PermissionRequest>();
            for (Map.Entry<String, GuavusAuthImpl.Resource> resource : permissionMap.entrySet()) {
                PermissionRequest permissionRequest = new PermissionRequest();
                permissionRequest.setResourceId(resource.getKey());
                permissionRequest.setScopes(new HashSet<>(resource.getValue().getScopes()));
                permissionRequests.add(permissionRequest);

            }
            if (!permissionMap.isEmpty())
                return permission.create(permissionRequests).getTicket();
        }
        return null;
    }

    protected boolean isAuthorized(Map<String, GuavusAuthImpl.Resource> permissionMap, AccessToken
            accessToken, OIDCHttpFacade httpFacade, Map<String, List<String>> claims) {
        HttpFacade.Request request = httpFacade.getRequest();

        if (isDefaultAccessDeniedUri(request)) {
            return true;
        }

        AccessToken.Authorization authorization = accessToken.getAuthorization();

        if (authorization == null) {
            return false;
        }

        Collection<Permission> grantedPermissions = authorization.getPermissions();
        HashMap<String, Permission> grantedPermissionMap = new HashMap<>();
        for (Permission permission : grantedPermissions) {
            grantedPermissionMap.put(permission.getResourceId(), permission);
        }

        for (Map.Entry<String, GuavusAuthImpl.Resource> resource : permissionMap.entrySet()) {
            if (!grantedPermissionMap.containsKey(resource.getKey()))
                return false;
            PolicyEnforcerConfig.MethodConfig methodConfig = new PolicyEnforcerConfig.MethodConfig();
            methodConfig.setScopes(permissionMap.get(resource.getKey()).getScopes());
            if (!hasResourceScopePermission(methodConfig, grantedPermissionMap.get(resource.getKey()))) {
                return false;
            }
        }
        return true;
    }

    private boolean hasResourceScopePermission(PolicyEnforcerConfig.MethodConfig methodConfig, Permission
            permission) {
        List<String> requiredScopes = methodConfig.getScopes();
        Set<String> allowedScopes = permission.getScopes();

        if (allowedScopes.isEmpty()) {
            return true;
        }
        return allowedScopes.containsAll(requiredScopes);
    }

    private void writeLogs(AuditLogs auditLogs, Map<String, Resource> permissionMap) {
        StringBuilder action = new StringBuilder();
        for (Map.Entry<String, Resource> resource : permissionMap.entrySet()) {
            action.append("Resource:#" + resource.getValue().getResourceName() + " scopes : " + resource.getValue().getScopes() + " ");
        }
        auditLogs.setAction(action.toString());
        auditLogs.setTimestamp(dateFormat.format(new Date()));
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
        String jsonString = null;
        try {
            jsonString = mapper.writeValueAsString(auditLogs);
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
        LOGGER.info(jsonString);
    }


    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedForHeader = request.getHeader("X-FORWARDED-FOR");
        if (xForwardedForHeader == null) {
            return request.getRemoteAddr();
        } else {
            return new StringTokenizer(xForwardedForHeader, ",").nextToken().trim();
        }
    }

}




