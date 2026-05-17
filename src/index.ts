import { APP_HTML, SPEC_MARKDOWN, SPEC_HTML } from "./generated";

const encoder = new TextEncoder();

export default {
  fetch(request: Request): Response {
    const url = new URL(request.url);

    if (url.pathname === "/healthz") {
      return text("ok\n", "text/plain; charset=utf-8");
    }

    if (url.pathname === "/docs/spec.md") {
      return text(SPEC_MARKDOWN, "text/markdown; charset=utf-8");
    }

    if (url.pathname === "/docs/spec" || url.pathname === "/docs/spec/") {
      if (wantsMarkdown(request)) {
        return text(SPEC_MARKDOWN, "text/markdown; charset=utf-8", { vary: "Accept" });
      }

      return text(SPEC_HTML, "text/html; charset=utf-8", { vary: "Accept" });
    }

    if (url.pathname === "/" || url.pathname === "/app" || url.pathname === "/app/") {
      return text(APP_HTML, "text/html; charset=utf-8", { vary: "Accept" });
    }

    return new Response("Not found\n", {
      status: 404,
      headers: securityHeaders("text/plain; charset=utf-8"),
    });
  },
} satisfies ExportedHandler<Env>;

function wantsMarkdown(request: Request): boolean {
  const accept = request.headers.get("accept") ?? "";
  return accept.includes("text/markdown");
}

function text(body: string, contentType: string, extraHeaders: HeadersInit = {}): Response {
  return new Response(body, {
    headers: {
      ...securityHeaders(contentType),
      ...extraHeaders,
      "content-length": String(encoder.encode(body).byteLength),
    },
  });
}

function securityHeaders(contentType: string): HeadersInit {
  return {
    "content-type": contentType,
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "cache-control": "public, max-age=300",
  };
}
