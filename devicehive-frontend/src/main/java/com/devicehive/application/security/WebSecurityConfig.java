package com.devicehive.application.security;

import com.devicehive.application.filter.BasicAuthenticationFilter;
import com.devicehive.auth.SkipPathRequestMatcher;
import com.devicehive.auth.jwt.extractor.TokenExtractor;

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

import com.devicehive.auth.rest.JwtTokenAuthenticationProcessingFilter;
import com.devicehive.auth.rest.SimpleCORSFilter;
import com.devicehive.auth.rest.providers.BasicAuthenticationProvider;
import com.devicehive.auth.rest.providers.HiveAnonymousAuthenticationProvider;
import com.devicehive.auth.rest.providers.JwtTokenAuthenticationProvider;
import com.devicehive.model.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletResponse;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Configuration
@EnableWebSecurity
@Order(Ordered.HIGHEST_PRECEDENCE)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	public static final String JWT_TOKEN_HEADER_PARAM = "X-Authorization";
	public static final String FORM_BASED_LOGIN_ENTRY_POINT = "/dh/rest/login";
	public static final String TOKEN_BASED_AUTH_ENTRY_POINT = "/dh/**";
    public static final String TOKEN_REFRESH_ENTRY_POINT = "/dh/rest/token";

    @Autowired
    private TokenExtractor tokenExtractor;
    @Autowired
    private ObjectMapper objectMapper;

    private Gson gson = new GsonBuilder().create();

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .exceptionHandling()
                .authenticationEntryPoint(unauthorizedEntryPoint())
                .and()
                	.anonymous().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                	.authorizeRequests()
		                .antMatchers("/css/**", "/server/**", "/scripts/**", "/webjars/**", "/templates/**").permitAll()
		                .antMatchers("/*/swagger.json", "/*/swagger.yaml", "/dh/rest/swagger.json").permitAll()
		                .antMatchers(FORM_BASED_LOGIN_ENTRY_POINT, TOKEN_REFRESH_ENTRY_POINT).permitAll()
		        .and()
                	.authorizeRequests()
                		.antMatchers(TOKEN_BASED_AUTH_ENTRY_POINT).authenticated()
        		.and()
	        		.addFilterBefore(buildBasicAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
	                .addFilterBefore(buildJwtTokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
	                .addFilterAfter(new SimpleCORSFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .authenticationProvider(basicAuthenticationProvider())
                .authenticationProvider(jwtTokenAuthenticationProvider())
                .authenticationProvider(anonymousAuthenticationProvider());
    }
    
    protected BasicAuthenticationFilter buildBasicAuthenticationFilter() throws Exception {
    	BasicAuthenticationFilter filter = new BasicAuthenticationFilter(FORM_BASED_LOGIN_ENTRY_POINT, objectMapper);
        filter.setAuthenticationManager(authenticationManager());
        return filter;
    }
    
    protected JwtTokenAuthenticationProcessingFilter buildJwtTokenAuthenticationFilter() throws Exception {
        List<String> pathsToSkip = Arrays.asList(TOKEN_REFRESH_ENTRY_POINT, FORM_BASED_LOGIN_ENTRY_POINT);
        SkipPathRequestMatcher matcher = new SkipPathRequestMatcher(pathsToSkip, TOKEN_BASED_AUTH_ENTRY_POINT);
        return new JwtTokenAuthenticationProcessingFilter(authenticationManager(), tokenExtractor, matcher);
    }
    
    @Bean
    @Primary
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public BasicAuthenticationProvider basicAuthenticationProvider() {
        return new BasicAuthenticationProvider();
    }

    @Bean
    public JwtTokenAuthenticationProvider jwtTokenAuthenticationProvider() {
        return new JwtTokenAuthenticationProvider();
    }

    @Bean
    public HiveAnonymousAuthenticationProvider anonymousAuthenticationProvider() {
        return new HiveAnonymousAuthenticationProvider();
    }

    @Bean
    public AuthenticationEntryPoint unauthorizedEntryPoint() {
        return (request, response, authException) -> {
            Optional<String> authHeader = Optional.ofNullable(request.getHeader(HttpHeaders.AUTHORIZATION));
//            if (authHeader.isPresent() && authHeader.get().startsWith(Constants.TOKEN_SCHEME)) {
//                response.addHeader(HttpHeaders.WWW_AUTHENTICATE, Messages.OAUTH_REALM);
//            } else {
//                response.addHeader(HttpHeaders.WWW_AUTHENTICATE, Messages.BASIC_REALM);
//            }
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getOutputStream().println(
                    gson.toJson(new ErrorResponse(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage())));
        };
    }
}
