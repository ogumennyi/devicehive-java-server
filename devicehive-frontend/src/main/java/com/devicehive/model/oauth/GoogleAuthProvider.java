package com.devicehive.model.oauth;

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

import com.devicehive.configuration.Constants;
import com.devicehive.configuration.Messages;
import com.devicehive.exceptions.HiveException;
import com.devicehive.model.enums.UserStatus;
import com.devicehive.service.IdentityProviderService;
import com.devicehive.service.OAuthTokenService;
import com.devicehive.service.UserService;
import com.devicehive.service.configuration.ConfigurationService;
import com.devicehive.vo.*;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.validation.constraints.NotNull;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;

import static javax.ws.rs.core.Response.Status.UNAUTHORIZED;

/**
 * Created by tmatvienko on 1/9/15.
 */
@Component
public class GoogleAuthProvider extends AuthProvider {
    private static final Logger logger = LoggerFactory.getLogger(GoogleAuthProvider.class);

    private static final String GOOGLE_PROVIDER_NAME = "Google";

    private IdentityProviderVO identityProvider;

    @Autowired
    private IdentityProviderService identityProviderService;
    @Autowired
    private Environment env;
    @Autowired
    private ConfigurationService configurationService;
    @Autowired
    private UserService userService;
    @Autowired
    private OAuthTokenService tokenService;
    @Autowired
    private IdentityProviderUtils identityProviderUtils;

    @PostConstruct
    private void initialize() {
        identityProvider = identityProviderService.find(Constants.GOOGLE_IDENTITY_PROVIDER_ID);
    }

    @Override
    public boolean isIdentityProviderAllowed() {
        return Boolean.valueOf(configurationService.get(Constants.GOOGLE_IDENTITY_ALLOWED));
    }

    @Override
    public JwtTokenVO createAccessKey(@NotNull final OauthJwtRequestVO request) {
        if (isIdentityProviderAllowed()) {
            final String accessToken = request.getAccessToken() == null ? getAccessToken(request.getCode(), request.getRedirectUri()) : request.getAccessToken();
            final String userEmail = getIdentityProviderEmail(accessToken);
            final UserVO user = findUser(userEmail);
            return tokenService.authenticate(user);
        }
        logger.error(String.format(Messages.IDENTITY_PROVIDER_NOT_ALLOWED, GOOGLE_PROVIDER_NAME));
        throw new HiveException(String.format(Messages.IDENTITY_PROVIDER_NOT_ALLOWED, GOOGLE_PROVIDER_NAME),
                Response.Status.UNAUTHORIZED.getStatusCode());
    }

    private String getAccessToken(final String code, final String redirectUrl) {
        if (StringUtils.isBlank(code) || StringUtils.isBlank(redirectUrl)) {
            logger.error(Messages.INVALID_AUTH_REQUEST_PARAMETERS);
            throw new HiveException(Messages.INVALID_AUTH_REQUEST_PARAMETERS, Response.Status.BAD_REQUEST.getStatusCode());
        }
        final String endpoint = identityProvider.getTokenEndpoint();
        Map<String, String> params = new HashMap<>();
        params.put("code", code);
        params.put("client_id", configurationService.get(Constants.GOOGLE_IDENTITY_CLIENT_ID));
        params.put("client_secret", configurationService.get(Constants.GOOGLE_IDENTITY_CLIENT_SECRET));
        params.put("redirect_uri", redirectUrl);
        params.put("grant_type", "authorization_code");
        final String response = identityProviderUtils.executePost(new NetHttpTransport(), params, endpoint, GOOGLE_PROVIDER_NAME);
        final JsonObject jsonObject = new JsonParser().parse(response).getAsJsonObject();
        try {
            return jsonObject.get("access_token").getAsString();
        } catch (IllegalStateException ex) {
            logger.error("Exception has been caught during Identity Provider GET request execution", response);
            throw new HiveException(String.format(Messages.OAUTH_ACCESS_TOKEN_VERIFICATION_FAILED, GOOGLE_PROVIDER_NAME, response),
                    Response.Status.UNAUTHORIZED.getStatusCode());
        }
    }

    private String getIdentityProviderEmail(final String accessToken) {
        final JsonElement verificationResponse = getVerificationResponse(accessToken);
        final JsonElement verificationElement = verificationResponse.getAsJsonObject().get("issued_to");
        final boolean isValid = verificationElement != null && verificationElement.getAsString().startsWith(
                configurationService.get(Constants.GOOGLE_IDENTITY_CLIENT_ID));
        if (!isValid) {
            logger.error("OAuth token verification for Google identity provider failed. Provider response: {}", verificationResponse);
            throw new HiveException(String.format(Messages.OAUTH_ACCESS_TOKEN_VERIFICATION_FAILED,
                    GOOGLE_PROVIDER_NAME), Response.Status.UNAUTHORIZED.getStatusCode());
        }
        return verificationResponse.getAsJsonObject().get("email").getAsString();
    }

    private UserVO findUser(final String email) {
        final UserVO user = userService.findGoogleUser(email);
        if (user == null) {
            logger.error("No user with email {} found for identity provider {}", email, GOOGLE_PROVIDER_NAME);
            throw new HiveException(Messages.USER_NOT_FOUND, Response.Status.UNAUTHORIZED.getStatusCode());
        } else if (user.getStatus() != UserStatus.ACTIVE) {
            logger.error("User {} is locked, disabled or deleted", email);
            throw new HiveException(Messages.USER_NOT_ACTIVE, UNAUTHORIZED.getStatusCode());
        }
        return user;
    }

    private JsonElement getVerificationResponse(final String accessToken) {
        return identityProviderUtils.executeGet(new NetHttpTransport(),
                BearerToken.queryParameterAccessMethod(), accessToken,
                identityProvider.getVerificationEndpoint(), GOOGLE_PROVIDER_NAME);
    }
}
