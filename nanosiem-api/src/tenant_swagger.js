// SPDX-License-Identifier: AGPL-3.0-or-later

// Tenant-local Swagger assets and requests; no external validator or persisted credentials.
window.onload = function () {
  const match = window.location.pathname.match(/^\/t\/([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\/swagger-ui\/$/);
  if (!match) throw new Error("Invalid tenant documentation URL");
  const base = "/t/" + match[1];
  window.ui = SwaggerUIBundle({
    url: base + "/api-docs/openapi.json",
    dom_id: "#swagger-ui",
    deepLinking: true,
    validatorUrl: null,
    persistAuthorization: false,
    withCredentials: false,
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
    layout: "StandaloneLayout",
    requestInterceptor: function (request) {
      const target = new URL(request.url, window.location.origin);
      if (target.origin !== window.location.origin ||
          !(target.pathname === base + "/api-docs/openapi.json" ||
            target.pathname.startsWith(base + "/api/"))) {
        throw new Error("Request must stay within this tenant");
      }
      request.credentials = "omit";
      request.headers = request.headers || {};
      // Keys are the sole Swagger credential; bearer/cookie session flows have
      // separate CSRF and refresh requirements handled by the SPA.
      for (const name of Object.keys(request.headers)) {
        if (["authorization", "cookie"].includes(name.toLowerCase())) delete request.headers[name];
      }
      return request;
    }
  });
};
