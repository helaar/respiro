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

package org.kantega.respiro.documenter;

import fj.Show;
import fj.data.Stream;

import static org.kantega.respiro.documenter.Strings.nil;
import static org.kantega.respiro.documenter.Strings.nl;

public class ExchangeDocumentation {
    public static final Show<ExchangeDocumentation> loggerShow =
      Show.show(ed-> nil.append(Stream.fromString("Request:")).append(nl)
        .append(Stream.fromString(ed.requestDocumentation.url)).append(nl)
        .append(Stream.fromString(ed.requestDocumentation.body)).append(nl)
        .append(Stream.fromString("Response: ")).append(Stream.fromString(ed.responseDocumentation.status)).append(nl)
        .append(Stream.fromString(ed.responseDocumentation.body)));

    public final RequestDocumentation requestDocumentation;
    public final ResponseDocumentation responseDocumentation;

    public ExchangeDocumentation(RequestDocumentation requestDocumentation, ResponseDocumentation responseDocumentation) {
        this.requestDocumentation = requestDocumentation;
        this.responseDocumentation = responseDocumentation;
    }

    @Override
    public String toString() {
        return "ExchangeDocumentation{" +
          "requestDocumentation=" + requestDocumentation +
          ", responseDocumentation=" + responseDocumentation +
          '}';
    }
}
