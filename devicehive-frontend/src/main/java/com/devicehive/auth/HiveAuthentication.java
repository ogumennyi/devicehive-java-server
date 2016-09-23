package com.devicehive.auth;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.net.InetAddress;
import java.util.Collection;

public class HiveAuthentication extends PreAuthenticatedAuthenticationToken {
    private HivePrincipal hivePrincipal;

    public HiveAuthentication(Object aPrincipal, Collection<? extends GrantedAuthority> anAuthorities) {
        super(aPrincipal, null, anAuthorities);
    }

    public HiveAuthentication(Object aPrincipal) {
        super(aPrincipal, null);
    }

    public HivePrincipal getHivePrincipal() {
        return hivePrincipal;
    }

    public void setHivePrincipal(HivePrincipal hivePrincipal) {
        this.hivePrincipal = hivePrincipal;
    }

    public static class HiveAuthDetails {
        private InetAddress clientInetAddress;
        private String origin;
        private String authorization;

        public HiveAuthDetails(InetAddress clientInetAddress, String origin, String authorization) {
            this.clientInetAddress = clientInetAddress;
            this.origin = origin;
            this.authorization = authorization;
        }

        public InetAddress getClientInetAddress() {
            return clientInetAddress;
        }

        public String getOrigin() {
            return origin;
        }

        public String getAuthorization() {
            return authorization;
        }
    }
}
