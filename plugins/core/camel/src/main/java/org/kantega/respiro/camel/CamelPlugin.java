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

package org.kantega.respiro.camel;

import org.apache.camel.CamelContext;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.impl.DefaultCamelContext;
import org.apache.camel.impl.SimpleRegistry;
import org.kantega.reststop.api.Export;
import org.kantega.reststop.api.Plugin;

import javax.annotation.PreDestroy;
import java.util.Collection;

/**
 *
 */
@Plugin
public class CamelPlugin implements CamelRouteDeployer {

    private final Collection<CamelContextCustomizer> camelContextCustomizers;

    private CamelContext camelContext;

    private SimpleRegistry simpleRegistry = new SimpleRegistry();

    @Export final CamelRouteDeployer camelRouteDeployer = this;

    @Export final CamelRegistry camelRegistry = new SimpleCamelRegistry(simpleRegistry);

    public CamelPlugin(Collection<CamelContextCustomizer> camelContextCustomizers) throws Exception {
        this.camelContextCustomizers = camelContextCustomizers;
    }

    @Override
    public void deploy(Collection<RouteBuilder> routeBuilders) {
        try {
            camelContext = new DefaultCamelContext(simpleRegistry);

            camelContextCustomizers.forEach(c -> c.customize(camelContext));

            for (RouteBuilder routeBuilder : routeBuilders) {
                camelContext.addRoutes(routeBuilder);
            }
            camelContext.start();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @PreDestroy
    public void stop() throws Exception {
        camelContext.stop();

    }

    private class SimpleCamelRegistry implements CamelRegistry {
        private final SimpleRegistry simpleRegistry;

        public SimpleCamelRegistry(SimpleRegistry simpleRegistry) {
            this.simpleRegistry = simpleRegistry;
        }

        @Override
        public void add(String name, Object component) {
            simpleRegistry.put(name, component);
        }

        @Override
        public void remove(String name) {
            simpleRegistry.remove(name);
        }
    }
}


