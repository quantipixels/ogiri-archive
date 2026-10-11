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

    public static void unauthorized(
            jakarta.servlet.http.HttpServletRequest request,
            HttpServletResponse response,
            String base)
            throws IOException {
        String path = OgiriConfigurer.path(request);
        String mounted = OgiriConfigurer.mount(request, base);
        if (path.equals(mounted + "/validate_token")) {
            write(
                    response,
                    401,
                    Map.of("success", false, "errors", List.of("Invalid login credentials")));
        } else if (path.equals(mounted + "/sign_out")) {
            write(
                    response,
                    404,
                    Map.of(
                            "success",
                            false,
                            "errors",
                            List.of("User was not found or was not logged in.")));
        } else if (path.equals(mounted + "/password")) {
            write(response, 401, Map.of("success", false, "errors", List.of("Unauthorized")));
        } else if (path.equals(mounted) || path.equals(mounted + "/")) {
            String message =
                    request.getMethod().equals("DELETE")
                            ? "Unable to locate account for destruction."
                            : "User not found.";
            write(
                    response,
                    404,
                    Map.of("success", false, "status", "error", "errors", List.of(message)));
        } else {
            unauthorized(response);
        }
    }

    public static void forbidden(HttpServletResponse response) throws IOException {
        write(
                response,
                403,
                Map.of("errors", List.of("You are not authorized to access this resource.")));
    }

    public static void csrf(HttpServletResponse response) throws IOException {
        write(response, 403, Map.of("success", false, "errors", List.of("Invalid CSRF token")));
    }

    public static void unavailable(HttpServletResponse response) throws IOException {
        write(response, 503, DtaFailure.unavailable());
    }
}
