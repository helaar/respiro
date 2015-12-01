/*
 * Copyright 2015 Kantega AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.kantega.respiro.security;

import org.kantega.reststop.api.*;

import javax.servlet.Filter;
import java.util.concurrent.TimeUnit;


/**
 * Created by helaar on 15.10.2015.
 */
@Plugin
public class SecurityPlugin  {

    @Export
    private final Filter basicAuthFilter;


    public SecurityPlugin(@Config(defaultValue = "NTE-Netty") String securityRealm,
                          @Config(defaultValue = "5") int passwordCacheValidityMinutes,
                          ServletBuilder servletBuilder,
                          PasswordChecker passwordChecker) {

        if( passwordCacheValidityMinutes > 0)
            passwordChecker = new CachingPasswordChecker(passwordChecker, passwordCacheValidityMinutes, TimeUnit.MINUTES);

        basicAuthFilter = servletBuilder.filter(new BasicAuthenticationFilter(securityRealm, passwordChecker), "/*", FilterPhase.AUTHENTICATION);
    }
}
