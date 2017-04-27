package com.devicehive.auth.rest;

import com.devicehive.application.security.WebSecurityConfig;

/*
 * #%L
 * DeviceHive Java Server Common business logic
 * %%
 * Copyright (C) 2016 DataArt
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import com.devicehive.auth.HiveAuthentication;
import com.devicehive.auth.jwt.extractor.TokenExtractor;
import com.devicehive.configuration.Constants;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.util.UrlPathHelper;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Optional;
import java.util.UUID;

public class JwtTokenAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenAuthenticationProcessingFilter.class);

    private AuthenticationManager authenticationManager;
    private final TokenExtractor tokenExtractor;

    public JwtTokenAuthenticationProcessingFilter(AuthenticationManager authenticationManager, TokenExtractor tokenExtractor, RequestMatcher matcher) {
    	super(matcher);
        this.authenticationManager = authenticationManager;
        this.tokenExtractor = tokenExtractor;
    }
    
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        String tokenPayload = request.getHeader(WebSecurityConfig.JWT_TOKEN_HEADER_PARAM);
        RawAccessJwtToken token = new RawAccessJwtToken(tokenExtractor.extract(tokenPayload));
        return getAuthenticationManager().authenticate(new JwtAuthenticationToken(token));
    }

//    @Override
//    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
//        HttpServletRequest httpRequest = (HttpServletRequest) request;
//        HttpServletResponse httpResponse = (HttpServletResponse) response;
//
//        Optional<String> authHeader = Optional.ofNullable(httpRequest.getHeader(HttpHeaders.AUTHORIZATION));
//
//        String resourcePath = new UrlPathHelper().getPathWithinApplication(httpRequest);
//        logger.debug("Security intercepted request to {}", resourcePath);
//
//        try {
//            if (authHeader.isPresent()) {
//                String header = authHeader.get();
//                if (header.startsWith(Constants.BASIC_AUTH_SCHEME)) {
//                    processBasicAuth(header);
//                } else if (header.startsWith(Constants.TOKEN_SCHEME)) {
//                    processJwtAuth(authHeader.get().substring(6).trim());
//                }
//            } else {
//                processAnonymousAuth();
//            }
//
//            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//            if (authentication != null && authentication instanceof AbstractAuthenticationToken) {
//                MDC.put("usrinf", authentication.getName());
//                HiveAuthentication.HiveAuthDetails details = createUserDetails(httpRequest);
//                ((AbstractAuthenticationToken) authentication).setDetails(details);
//            }
//
//            chain.doFilter(request, response);
//        } catch (InternalAuthenticationServiceException e) {
//            SecurityContextHolder.clearContext();
//            logger.error("Internal authentication service exception", e);
//            httpResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
//        } catch (AuthenticationException e) {
//            SecurityContextHolder.clearContext();
//            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
//        } finally {
//            MDC.remove("usrinf");
//        }
//    }

    private HiveAuthentication.HiveAuthDetails createUserDetails(HttpServletRequest request) throws UnknownHostException {
        return new HiveAuthentication.HiveAuthDetails(
                InetAddress.getByName(request.getRemoteAddr()),
                request.getHeader(HttpHeaders.ORIGIN),
                request.getHeader(HttpHeaders.AUTHORIZATION));
    }

    private void processBasicAuth(String authHeader) throws UnsupportedEncodingException {
        Pair<String, String> credentials = extractAndDecodeHeader(authHeader);
        UsernamePasswordAuthenticationToken requestAuth = new UsernamePasswordAuthenticationToken(credentials.getLeft().trim(), credentials.getRight().trim());
        tryAuthenticate(requestAuth);
    }

    private void processJwtAuth(String token) {
        PreAuthenticatedAuthenticationToken requestAuth = new PreAuthenticatedAuthenticationToken(token, null);
        tryAuthenticate(requestAuth);
    }

    private void processKeyAuth(String key) {
        PreAuthenticatedAuthenticationToken requestAuth = new PreAuthenticatedAuthenticationToken(key, null);
        tryAuthenticate(requestAuth);
    }

    private void processAnonymousAuth() {
        AnonymousAuthenticationToken requestAuth = new AnonymousAuthenticationToken(UUID.randomUUID().toString(), "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
        tryAuthenticate(requestAuth);
    }

    private void tryAuthenticate(Authentication requestAuth) {
        Authentication authentication = authenticationManager.authenticate(requestAuth);
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new InternalAuthenticationServiceException("Unable to authenticate user with provided credetials");
        }
        logger.debug("Successfully authenticated");
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private Pair<String, String> extractAndDecodeHeader(String header) throws UnsupportedEncodingException {
        byte[] base64Token = header.substring(6).getBytes("UTF-8");
        byte[] decoded;
        try {
            decoded = Base64.decode(base64Token);
        } catch (IllegalArgumentException e) {
            throw new BadCredentialsException("Failed to decode basic authentication token");
        }
        String token = new String(decoded, "UTF-8");
        int delim = token.indexOf(":");
        if (delim == -1) {
            throw new BadCredentialsException("Invalid basic authentication token");
        }
        return Pair.of(token.substring(0, delim), token.substring(delim + 1));
    }
}
