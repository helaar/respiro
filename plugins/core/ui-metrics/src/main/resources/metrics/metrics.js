/*
 * Copyright 2019 Kantega AS
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
 */

angular
    .module("respiro.metrics", ["respiro"])
    .config(function(respiroMenuProvider) {
        respiroMenuProvider
            .add(
                {
                    href: "/metrics",
                    label: "Metrics"
                })
    })
    .config(function ($routeProvider) {

        $routeProvider
            .when('/metrics', {
                controller: 'MetricsController as metrics',
                templateUrl: 'partials/metrics.html',
            })
    })
    .controller("MetricsController", function ($http, $scope) {
        $http.get("../metrics/")
            .then(function (data) {
                    var resources = new Array();
                    var endpoints = new Array();

                    var timers = data.data.timers;
                    for (var name in timers) {
                        if(name.indexOf("REST.") == 0) {
                            var timer = timers[name];
                            var rest = name.substr("REST.".length);
                            var method = rest.substr(0, rest.indexOf("."));
                            var path = rest.substr(rest.indexOf(".") + 1);
                            resources.push({name: name, method: method, path: path, timer: timer});
                        } else if(name.indexOf("SOAP.") == 0) {
                            var timer = timers[name];
                            var rest = name.substr("SOAP.".length);
                            var serviceStart = 0
                            var operationStart = rest.indexOf(".", serviceStart+1);
                            var pathStart = rest.indexOf(".", operationStart+1);

                            endpoints.push({
                                name: name,
                                service: rest.substr(serviceStart, operationStart-serviceStart),
                                operation: rest.substr(operationStart +1, pathStart-operationStart-1),
                                path: rest.substr(pathStart),
                                timer: timer});
                        }
                    }

                    $scope.resources = resources;
                    $scope.endpoints = endpoints;
                },
                function () {
                    console.log("Error fetching metrics")
                });
    });


respiro.module("respiro.metrics");
