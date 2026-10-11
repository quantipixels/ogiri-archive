// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security;

import com.quantipixels.ogiri.DtaFailure;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import tools.jackson.databind.json.JsonMapper;

public final class DtaErrors {
    private static final JsonMapper JSON = JsonMapper.builder().build();

    private DtaErrors() {}

    public static void write(HttpServletResponse response, int status, Map<String, ?> body)
            throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setHeader("Cache-Control", "no-store");
        response.getWriter().write(JSON.writeValueAsString(body));
    }

    public static void unauthorized(HttpServletResponse response) throws IOException {
        write(
                response,
                401,
                Map.of("errors", List.of("You need to sign in or sign up before continuing.")));
    }

    public static void forbidden(HttpServletResponse response) throws IOException {
        write(
                response,
                403,
                Map.of("errors", List.of("You are not authorized to access this resource.")));
    }

    public static void unavailable(HttpServletResponse response) throws IOException {
        write(response, 503, DtaFailure.unavailable());
    }
}
