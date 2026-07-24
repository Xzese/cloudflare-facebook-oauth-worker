import {
	accessRejection,
	isLoopbackHostname,
	verifyAccessJwt,
	type AccessIdentityRequirement,
	type AccessVerifier,
} from "./access.ts";

interface RuntimeDashboardVariables {
	APP_ID: string;
	GRAPH_SCOPE: string;
	GRAPH_API_VERSION: string;
	TEAM_DOMAIN: string;
	POLICY_AUD: string;
}

export type Env = Cloudflare.Env & RuntimeDashboardVariables;

export interface StoredToken {
	accessToken: string;
	expiresAt: string | null;
	updatedAt: string;
	dataAccessExpiresAt?: string | null;
}

interface TokenResponse {
	access_token?: string;
	expires_in?: number;
}

interface DebugTokenResponse {
	data?: {
		data_access_expires_at?: number;
		expires_at?: number;
	};
}

interface WorkerDependencies {
	verifyAccess: AccessVerifier;
}

interface RouteDefinition {
	operation: string;
	identity: AccessIdentityRequirement;
	handle: (request: Request, env: Env) => Promise<Response>;
}

const TOKEN_KEY = "facebook:access-token";
const STATE_COOKIE = "facebook_oauth_state";
const DEFAULT_GRAPH_API_VERSION = "v25.0";
const FALLBACK_TOKEN_EXPIRY_DAYS = 90;
const CONTENT_SECURITY_POLICY = [
	"default-src 'none'",
	"base-uri 'none'",
	"form-action 'self' https://www.facebook.com https://facebook.com",
	"frame-ancestors 'none'",
	"style-src 'unsafe-inline'",
].join("; ");

function escapeHtml(value: string): string {
	return value
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#039;");
}

export function getPublicBaseUrl(request: Request): URL {
	const requestUrl = new URL(request.url);
	const loopbackLocalDevelopment = isLoopbackHostname(requestUrl.hostname);
	if (
		requestUrl.protocol !== "https:" &&
		!(requestUrl.protocol === "http:" && loopbackLocalDevelopment)
	) {
		throw new Error("The request origin must use HTTPS.");
	}

	return new URL(requestUrl.origin);
}

export function getRedirectUri(request: Request): string {
	return new URL("/callback", getPublicBaseUrl(request)).toString();
}

function getGraphApiBase(env: Env): string {
	return `https://graph.facebook.com/${env.GRAPH_API_VERSION || DEFAULT_GRAPH_API_VERSION}`;
}

export function createState(): string {
	const bytes = crypto.getRandomValues(new Uint8Array(32));
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function getCookie(request: Request, name: string): string | null {
	const cookieHeader = request.headers.get("cookie");
	if (!cookieHeader) {
		return null;
	}

	for (const cookie of cookieHeader.split(";")) {
		const [cookieName, ...valueParts] = cookie.trim().split("=");
		if (cookieName === name) {
			try {
				return decodeURIComponent(valueParts.join("="));
			} catch {
				return null;
			}
		}
	}

	return null;
}

function stateCookie(state: string, publicBaseUrl: URL): string {
	const secure = publicBaseUrl.protocol === "https:" ? "; Secure" : "";
	return `${STATE_COOKIE}=${encodeURIComponent(state)}; Path=/callback; HttpOnly; SameSite=Lax; Max-Age=600${secure}`;
}

function clearStateCookie(publicBaseUrl: URL): string {
	const secure = publicBaseUrl.protocol === "https:" ? "; Secure" : "";
	return `${STATE_COOKIE}=; Path=/callback; HttpOnly; SameSite=Lax; Max-Age=0${secure}`;
}

export function statesMatch(expected: string, received: string): boolean {
	const comparedLength = Math.max(expected.length, received.length);
	let difference = expected.length ^ received.length;

	for (let index = 0; index < comparedLength; index += 1) {
		difference |= (expected.charCodeAt(index) || 0) ^ (received.charCodeAt(index) || 0);
	}

	return difference === 0;
}

function isAuthorizedTokenRequest(request: Request, env: Env): boolean {
	const authorization = request.headers.get("authorization");
	if (!authorization?.startsWith("Bearer ") || !env.TOKEN_API_KEY) {
		return false;
	}

	return statesMatch(env.TOKEN_API_KEY, authorization.slice(7));
}

function tokenHasExpired(token: StoredToken): boolean | null {
	if (!token.expiresAt) {
		return null;
	}

	const expiresAt = Date.parse(token.expiresAt);
	return Number.isNaN(expiresAt) ? null : expiresAt <= Date.now();
}

function getRemainingTime(expiresAt: string | null): string {
	if (!expiresAt) {
		return "Unknown";
	}

	const expiry = Date.parse(expiresAt);
	if (Number.isNaN(expiry)) {
		return "Unknown";
	}

	const remainingMs = expiry - Date.now();
	if (remainingMs <= 0) {
		return "Expired";
	}

	const totalSeconds = Math.floor(remainingMs / 1000);
	const days = Math.floor(totalSeconds / 86_400);
	const hours = Math.floor((totalSeconds % 86_400) / 3600);
	const minutes = Math.floor((totalSeconds % 3600) / 60);

	if (days > 0) {
		return `${days} day${days === 1 ? "" : "s"}, ${hours} hour${hours === 1 ? "" : "s"}, ${minutes} minute${minutes === 1 ? "" : "s"}`;
	}

	if (hours > 0) {
		return `${hours} hour${hours === 1 ? "" : "s"}, ${minutes} minute${minutes === 1 ? "" : "s"}`;
	}

	return `${minutes} minute${minutes === 1 ? "" : "s"}`;
}

function jsonResponse(value: unknown, init: ResponseInit = {}): Response {
	const headers = new Headers(init.headers);
	headers.set("content-type", "application/json; charset=utf-8");
	return new Response(JSON.stringify(value), { ...init, headers });
}

export function withSecurityHeaders(response: Response): Response {
	const secured = new Response(response.body, response);
	secured.headers.set("cache-control", "no-store");
	secured.headers.set("content-security-policy", CONTENT_SECURITY_POLICY);
	secured.headers.set("referrer-policy", "no-referrer");
	secured.headers.set("x-content-type-options", "nosniff");
	return secured;
}

async function getStoredToken(request: Request, env: Env): Promise<Response> {
	if (!isAuthorizedTokenRequest(request, env)) {
		return jsonResponse(
			{ error: "Unauthorized" },
			{
				status: 401,
				headers: { "www-authenticate": "Bearer" },
			},
		);
	}

	const token = await env.FACEBOOK_AUTH.get<StoredToken>(TOKEN_KEY, "json");
	if (!token) {
		return jsonResponse({ error: "No Facebook access token is stored." }, { status: 404 });
	}

	const expired = tokenHasExpired(token);
	if (expired) {
		return jsonResponse(
			{
				error: "The stored Facebook access token has expired.",
				expiresAt: token.expiresAt,
				updatedAt: token.updatedAt,
				expired: true,
			},
			{ status: 410 },
		);
	}

	return jsonResponse({
		accessToken: token.accessToken,
		expiresAt: token.expiresAt,
		updatedAt: token.updatedAt,
		expired,
	});
}

async function renderPage(request: Request, env: Env): Promise<string> {
	const storedToken = await env.FACEBOOK_AUTH.get<StoredToken>(TOKEN_KEY, "json");
	const expired = storedToken ? tokenHasExpired(storedToken) : null;
	const updatedAt = storedToken?.updatedAt ?? "Never";
	const expiresAt = storedToken?.expiresAt ?? "Unknown";
	const tokenValue = storedToken?.accessToken ?? "No token";
	const remainingTime = storedToken
		? expired
			? "Expired"
			: getRemainingTime(storedToken.expiresAt ?? null)
		: "No token";

	return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Facebook Authentication</title>
    <style>
      :root {
        color-scheme: light dark;
        font-family: Inter, ui-sans-serif, system-ui, sans-serif;
      }
      body {
        display: grid;
        min-height: 100vh;
        margin: 0;
        place-items: center;
        background: #f4f6f8;
        color: #17202a;
      }
      main {
        width: min(90vw, 36rem);
        padding: 2rem;
        border: 1px solid #d9dee3;
        border-radius: 0.75rem;
        background: #fff;
        box-shadow: 0 0.75rem 2rem rgb(0 0 0 / 8%);
      }
      h1 { margin-top: 0; font-size: 1.5rem; }
      dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.75rem 1rem; }
      dt { font-weight: 700; }
      dd { margin: 0; overflow-wrap: anywhere; }
      input.token-field {
        width: 100%;
        box-sizing: border-box;
        border: 1px solid #d9dee3;
        border-radius: 0.3rem;
        background: #f6f8fa;
        padding: 0.75rem 0.85rem;
        color: #17202a;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
        font-size: 0.95rem;
        min-height: 2.7rem;
      }
      button {
        width: 100%;
        margin-top: 1.5rem;
        padding: 0.8rem;
        border: 0;
        border-radius: 0.4rem;
        background: #1877f2;
        color: #fff;
        cursor: pointer;
        font-weight: 700;
      }
      p { line-height: 1.5; }
      .hint { color: #5f6b76; font-size: 0.9rem; overflow-wrap: anywhere; }
      @media (prefers-color-scheme: dark) {
        body { background: #111827; color: #f3f4f6; }
        main { border-color: #374151; background: #1f2937; }
        input.token-field { background: #111827; color: #e5e7eb; border-color: #374151; }
        .hint { color: #c2cad4; }
      }
    </style>
  </head>
  <body>
    <main>
      <h1>Facebook Authentication</h1>
      <dl>
        <dt>Token</dt>
        <dd><input class="token-field" type="text" readonly value="${escapeHtml(tokenValue)}"></dd>
        <dt>Updated</dt>
        <dd><input class="token-field" type="text" readonly value="${escapeHtml(updatedAt)}"></dd>
        <dt>Expires</dt>
        <dd><input class="token-field" type="text" readonly value="${escapeHtml(expiresAt)}"></dd>
        <dt>Remaining</dt>
        <dd>${escapeHtml(remainingTime)}</dd>
      </dl>
      <form action="/authenticate" method="post">
        <button type="submit">Authenticate with Facebook</button>
      </form>
      <p class="hint">
        Add this exact URI to the Facebook app's valid OAuth redirect URIs:
        ${escapeHtml(getRedirectUri(request))}
      </p>
    </main>
  </body>
</html>`;
}

async function startAuthentication(request: Request, env: Env): Promise<Response> {
	if (!env.APP_SECRET) {
		return new Response("Facebook authentication is not configured.", {
			status: 500,
		});
	}

	let publicBaseUrl: URL;
	try {
		publicBaseUrl = getPublicBaseUrl(request);
	} catch {
		return new Response("Facebook authentication is not configured.", {
			status: 500,
		});
	}

	const state = createState();
	const authorizationUrl = new URL(
		`https://www.facebook.com/${env.GRAPH_API_VERSION || DEFAULT_GRAPH_API_VERSION}/dialog/oauth`,
	);
	authorizationUrl.search = new URLSearchParams({
		client_id: env.APP_ID,
		redirect_uri: new URL("/callback", publicBaseUrl).toString(),
		state,
		scope: env.GRAPH_SCOPE,
		response_type: "code",
	}).toString();

	return new Response(null, {
		status: 302,
		headers: {
			location: authorizationUrl.toString(),
			"set-cookie": stateCookie(state, publicBaseUrl),
		},
	});
}

interface TokenExpiryInfo {
	expiresAt: string | null;
	dataAccessExpiresAt: string | null;
}

async function getTokenExpiry(
	accessToken: string,
	expiresIn: number | undefined,
	env: Env,
): Promise<TokenExpiryInfo> {
	let tokenExpiresAt: string | null = null;
	if (typeof expiresIn === "number") {
		tokenExpiresAt = new Date(Date.now() + expiresIn * 1000).toISOString();
	}

	const body = new URLSearchParams({
		input_token: accessToken,
		access_token: `${env.APP_ID}|${env.APP_SECRET}`,
	});
	let dataAccessExpiresAt: string | null = null;
	let debugExpiresAt: string | null = null;

	try {
		const response = await fetch(`${getGraphApiBase(env)}/debug_token`, {
			method: "POST",
			headers: {
				"content-type": "application/x-www-form-urlencoded",
			},
			body,
		});
		const result = (await response.json()) as DebugTokenResponse;
		const debugData = result?.data as Record<string, unknown> | undefined;

		if (!response.ok) {
			throw new Error("Facebook token debugging failed.");
		}

		console.info("Facebook debug_token response", {
			status: response.status,
			ok: response.ok,
			fields: debugData ? Object.keys(debugData) : [],
			data_access_expires_at: debugData?.data_access_expires_at,
			expires_at: debugData?.expires_at,
		});

		dataAccessExpiresAt = result.data?.data_access_expires_at
			? new Date(result.data.data_access_expires_at * 1000).toISOString()
			: null;
		debugExpiresAt = result.data?.expires_at
			? new Date(result.data.expires_at * 1000).toISOString()
			: null;
	} catch {
		console.error({
			event: "facebook_token_expiry_lookup",
			outcome: "failure",
			failureType: "debug_request_failed",
		});
	}

	const fallbackExpiresAt = new Date(
		Date.now() + FALLBACK_TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 1000,
	).toISOString();
	const preferredExpiresAt =
		dataAccessExpiresAt ?? debugExpiresAt ?? tokenExpiresAt ?? fallbackExpiresAt;

	return {
		expiresAt: preferredExpiresAt,
		dataAccessExpiresAt,
	};
}

async function exchangeCodeForToken(
	code: string,
	redirectUri: string,
	env: Env,
): Promise<StoredToken> {
	const body = new URLSearchParams({
		client_id: env.APP_ID,
		client_secret: env.APP_SECRET,
		grant_type: "authorization_code",
		redirect_uri: redirectUri,
		code,
	});
	const response = await fetch(`${getGraphApiBase(env)}/oauth/access_token`, {
		method: "POST",
		headers: {
			"content-type": "application/x-www-form-urlencoded",
		},
		body,
	});
	const responseText = await response.text();
	let result: TokenResponse = {};
	let parsedResponse = false;
	try {
		result = responseText ? (JSON.parse(responseText) as typeof result) : {};
		parsedResponse = true;
	} catch {
		// Keep the fallback shape. Never log the upstream response body because it
		// can contain access tokens, authorization codes, or credential details.
	}

	if (!response.ok || !result.access_token) {
		const failureType = !response.ok
			? "upstream_rejected"
			: !parsedResponse
				? "invalid_response"
				: "missing_access_token";
		console.error({
			event: "facebook_token_exchange",
			outcome: "failure",
			failureType,
			httpStatus: response.status,
		});
		throw new Error("Facebook token exchange failed.");
	}

	console.info("Facebook OAuth access token response", {
		status: response.status,
		ok: response.ok,
		fields: Object.keys(result),
		expires_in: result.expires_in,
		has_access_token: Boolean(result.access_token),
		token_type: (result as { token_type?: string }).token_type,
	});

	let expiresAt: string | null;
	let dataAccessExpiresAt: string | null;
	try {
		const expiryInfo = await getTokenExpiry(result.access_token, result.expires_in, env);
		expiresAt = expiryInfo.expiresAt;
		dataAccessExpiresAt = expiryInfo.dataAccessExpiresAt;
	} catch {
		console.error({
			event: "facebook_token_expiry_resolution",
			outcome: "failure",
			failureType: "expiry_resolution_failed",
		});
		expiresAt = null;
		dataAccessExpiresAt = null;
	}

	return {
		accessToken: result.access_token,
		expiresAt,
		updatedAt: new Date().toISOString(),
		dataAccessExpiresAt,
	};
}

async function handleCallback(request: Request, env: Env): Promise<Response> {
	const requestUrl = new URL(request.url);
	let publicBaseUrl: URL;
	try {
		publicBaseUrl = getPublicBaseUrl(request);
	} catch {
		return new Response("Facebook authentication is not configured.", {
			status: 500,
		});
	}

	const errorResponse = (message: string, status: number): Response =>
		new Response(message, {
			status,
			headers: { "set-cookie": clearStateCookie(publicBaseUrl) },
		});

	if (!env.APP_SECRET) {
		return errorResponse("Facebook authentication is not configured.", 500);
	}

	if (requestUrl.searchParams.has("error")) {
		return errorResponse("Facebook authorization failed.", 400);
	}

	const code = requestUrl.searchParams.get("code");
	const state = requestUrl.searchParams.get("state");
	const savedState = getCookie(request, STATE_COOKIE);
	if (!code || !state || !savedState) {
		return errorResponse("Missing authorization code or state.", 400);
	}

	if (!statesMatch(savedState, state)) {
		return errorResponse("The OAuth state is invalid or has expired.", 400);
	}

	if (!env.FACEBOOK_AUTH?.put) {
		console.error({
			event: "facebook_token_persistence",
			outcome: "failure",
			failureType: "storage_not_configured",
		});
		return errorResponse("Facebook token storage is not configured.", 500);
	}

	let token: StoredToken;
	try {
		token = await exchangeCodeForToken(code, getRedirectUri(request), env);
	} catch {
		return errorResponse("Unable to exchange Facebook token.", 502);
	}

	try {
		await env.FACEBOOK_AUTH.put(TOKEN_KEY, JSON.stringify(token));
	} catch {
		console.error({
			event: "facebook_token_persistence",
			outcome: "failure",
			failureType: "storage_write_failed",
		});
		return errorResponse("Unable to store Facebook token.", 502);
	}

	return new Response(null, {
		status: 302,
		headers: {
			location: new URL("/", publicBaseUrl).toString(),
			"set-cookie": clearStateCookie(publicBaseUrl),
		},
	});
}

function findRoute(request: Request): RouteDefinition | null {
	const url = new URL(request.url);

	if (request.method === "GET" && url.pathname === "/") {
		return {
			operation: "admin_page",
			identity: "human",
			handle: async (request, env) =>
				new Response(await renderPage(request, env), {
					headers: { "content-type": "text/html; charset=utf-8" },
				}),
		};
	}

	if (request.method === "POST" && url.pathname === "/authenticate") {
		return {
			operation: "start_authentication",
			identity: "human",
			handle: startAuthentication,
		};
	}

	if (request.method === "GET" && url.pathname === "/callback") {
		return {
			operation: "oauth_callback",
			identity: "human",
			handle: handleCallback,
		};
	}

	if (request.method === "GET" && url.pathname === "/api/token") {
		return {
			operation: "token_api",
			identity: "user-or-service",
			handle: getStoredToken,
		};
	}

	return null;
}

function safeErrorCategory(status: number): string {
	return status >= 500 ? "server_error" : "request_rejected";
}

function logRequest(operation: string, response: Response, startedAt: number): void {
	const failed = response.status >= 400;
	const event = {
		event: "worker_request",
		operation,
		status: failed ? "failure" : "success",
		durationMs: Date.now() - startedAt,
		...(failed ? { errorCategory: safeErrorCategory(response.status) } : {}),
	};

	if (failed) {
		console.error(event);
	} else {
		console.log(event);
	}
}

export function createWorker(dependencies: Partial<WorkerDependencies> = {}): ExportedHandler<Env> {
	const verifyAccess = dependencies.verifyAccess ?? verifyAccessJwt;

	return {
		async fetch(request: Request, env: Env): Promise<Response> {
			const startedAt = Date.now();
			const route = findRoute(request);
			const operation = route?.operation ?? "not_found";

			let response: Response;
			try {
				if (!route) {
					response = new Response("Not found", { status: 404 });
				} else {
					const rejection = await accessRejection(
						request,
						env,
						route.identity,
						verifyAccess,
					);
					response = rejection ?? (await route.handle(request, env));
				}
			} catch {
				response = new Response("Internal server error", { status: 500 });
			}

			const securedResponse = withSecurityHeaders(response);
			logRequest(operation, securedResponse, startedAt);
			return securedResponse;
		},
	};
}
