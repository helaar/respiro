/*
 * Copyright 2016 Kantega AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.kantega.respiro.security.jwt;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;

import javax.servlet.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Optional;
import java.util.stream.Stream;

import static org.kantega.respiro.security.jwt.JWTAuthenticationResult.UNAUTHORIZED;
import static org.slf4j.LoggerFactory.getLogger;

/**
 */
public class JWTAuthenticationFilter implements Filter {

    private static final Logger logger = getLogger(JWTAuthenticationFilter.class);

    private final JWTVerifier verifier;
    private final JWTConfig config;

    public JWTAuthenticationFilter(JWTVerifier verifier, JWTConfig config) {
        this.verifier = verifier;
        this.config = config;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        final HttpServletRequest req = (HttpServletRequest) request;
        final HttpServletResponse resp = (HttpServletResponse) response;
        if (Boolean.TRUE.equals(req.getAttribute("skipAuthentication"))) {
            // endponts that does not need to be protected
            chain.doFilter(req, resp);
            return;
        }

        AuthenticationResult authResult = authenticate(req);
        if (!authResult.isAuthenticated()) {
            resp.sendRedirect(createLoginUrl(req));
            return;
        } else {

            chain.doFilter(new HttpServletRequestWrapper(req) {
                @Override
                public boolean isUserInRole(String role) {
                    return authResult.isUserInRole(role);
                }

                @Override
                public String getRemoteUser() {
                    return authResult.getUsername();
                }

                @Override
                public Principal getUserPrincipal() {
                    return this::getRemoteUser;
                }
            }, resp);
        }
    }

    private AuthenticationResult authenticate(HttpServletRequest req) {

        final Optional<String> token = getTokenFromCookie(req);
        if (token.isPresent()) {
            try {

                DecodedJWT jwt = verifier.verify(token.get());

                return new JWTAuthenticationResult(jwt.getClaim("username"), jwt.getClaim("roles"));

            } catch (Throwable e) {
                logger.warn("Failed to validate JWT Token " + token, e);
                return UNAUTHORIZED;
            }
        } else
            return UNAUTHORIZED;

    }

    private Optional<String> getTokenFromCookie(HttpServletRequest req) {
        if (req.getCookies() != null)
            return Stream.of(req.getCookies())
                    .filter(c -> c.getName().equals(config.cookieName))
                    .findFirst().map(Cookie::getValue);
        else
            return Optional.empty();
    }


    private String createLoginUrl(HttpServletRequest req) {
        return config.loginUrl + req.getRequestURL().toString();
    }

    @Override
    public void destroy() {

    }


    static class JWTConfig {
        final String loginUrl;
        final String cookieName;

        public JWTConfig(String loginUrl, String cookieName) {
            this.loginUrl = loginUrl;
            this.cookieName = cookieName;
        }
    }
}
