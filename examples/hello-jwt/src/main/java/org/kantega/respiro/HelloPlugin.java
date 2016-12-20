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

package org.kantega.respiro;

import org.kantega.respiro.api.ApplicationBuilder;
import org.kantega.reststop.api.Export;
import org.kantega.reststop.api.FilterPhase;
import org.kantega.reststop.api.Plugin;
import org.kantega.reststop.api.ServletBuilder;

import javax.annotation.security.RolesAllowed;
import javax.servlet.Filter;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Application;

/**
 */
@Plugin
public class HelloPlugin {

    @Export
    final Application helloApplication;

    @Export
    final Filter loginFilter;

    public HelloPlugin(ApplicationBuilder builder, ServletBuilder servletBuilder) {
        helloApplication = builder
                .application()
                .singleton(new HelloResource())
                .build();
        loginFilter = servletBuilder.filter(new DummyLoginFilter(), "/login", FilterPhase.PRE_AUTHENTICATION);
    }

    @Path("/jwthello")
    public class HelloResource {


        @GET
        public String getHello() {
            return  "Hello unrestricted World";
        }

        @RolesAllowed("Restricted")
        @GET
        @Path("restricted")
        public String restricted() {
            return "Hello! Welcome to the privileged world.";
        }

        @RolesAllowed("Forbidden")
        @GET
        @Path("forbidden")
        public String forbidden() {
            return "You shall not pass!";
        }

    }
}
