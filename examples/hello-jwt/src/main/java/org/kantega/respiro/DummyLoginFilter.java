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

import javax.servlet.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 */
public class DummyLoginFilter implements Filter {

    private final String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiUmVzcGlybyIsIm5hbWUiOiJKb2huIERvZSIsInVzZXIiOiJqb2huZG9lIiwicm9sZXMiOlsiUmVzdHJpY3RlZCJdfQ.EPAo0l6mhkcKtogPbo9YVi4oiiQD7Pzd5aRpsAY5Ywi6vKoqsW86TXeqdJuJvLr8ljoclOvIEMu09twGqjichaiHdSil2zGiPMHUCIkbpxv23x_YeyzZRJW1iwv35CJRbOn2zfkLqNLaKD_5G_XyujtKycN2_Tg5KbdxeaxnN-4";

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletResponse resp = (HttpServletResponse) response;
        HttpServletRequest req = (HttpServletRequest) request;

        final Cookie cookie = new Cookie("respiro-auth-token", token);
        cookie.setHttpOnly(true);
        resp.addCookie(cookie);

        String callback = req.getParameter("callback");
        resp.sendRedirect(callback);

    }

    @Override
    public void destroy() {

    }
}
