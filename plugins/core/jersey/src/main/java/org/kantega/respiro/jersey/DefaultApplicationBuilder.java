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

package org.kantega.respiro.jersey;

import org.kantega.respiro.api.ApplicationBuilder;

import javax.ws.rs.core.Application;

/**
 * Created by helaar on 20.10.2015.
 */
public class DefaultApplicationBuilder implements ApplicationBuilder {
    @Override
    public ApplicationBuilder.Build application() {
        return new Build();
    }

    class Build implements ApplicationBuilder.Build {

        private JaxRsApplication application = new JaxRsApplication();

        @Override
        public ApplicationBuilder.Build singleton(Object resource) {
            application.addJaxRsSingletonResource(resource);
            return this;
        }

        @Override
        public ApplicationBuilder.Build resource(Class resClass) {
            application.addJaxRsContainerClass(resClass);
            return this;
        }

        @Override
        public ApplicationBuilder.Build property(String name, Object value) {
            application.setProperty(name, value);
            return this;
        }

        @Override
        public Application build() {
            return application;
        }
    }
}
