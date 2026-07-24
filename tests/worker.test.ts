import assert from "node:assert/strict";
import test from "node:test";

import {
	createWorker,
	getPublicBaseUrl,
	getRedirectUri,
	statesMatch,
	type Env,
	type StoredToken,
} from "../src/runtime.ts";
import type { AccessVerifier } from "../src/access.ts";

const TOKEN_KEY = "facebook:access-token";
const USER_ASSERTION = "valid-user-assertion";
const SERVICE_ASSERTION = "valid-service-assertion";

interface MemoryKv {
	namespace: KVNamespace;
	read: () => StoredToken | null;
}

function memoryKv(initial: StoredToken | null = null): MemoryKv {
	let value = initial ? JSON.stringify(initial) : null;

	return {
		namespace: {
			async get(_key: string, type?: string) {
				if (!value) {
					return null;
				}
				return type === "json" ? JSON.parse(value) : value;
			},
			async put(key: string, nextValue: string) {
				assert.equal(key, TOKEN_KEY);
				value = nextValue;
			},
		} as unknown as KVNamespace,
		read: () => (value ? (JSON.parse(value) as StoredToken) : null),
	};
}

function workerEnv(values: Partial<Env> = {}, kv = memoryKv()): Env {
	return {
		APP_ID: "test-app-id",
		APP_SECRET: "test-app-secret",
		FACEBOOK_AUTH: kv.namespace,
		GRAPH_API_VERSION: "v25.0",
		GRAPH_SCOPE: "pages_show_list,instagram_basic",
		POLICY_AUD: "test-audience",
		TEAM_DOMAIN: "https://example.cloudflareaccess.com",
		TOKEN_API_KEY: "test-token-api-key",
		...values,
	};
}

const verifyAccess: AccessVerifier = async (assertion) => {
	if (assertion === USER_ASSERTION) {
		return { kind: "user", email: "person@example.com", sub: "user-123" };
	}
	if (assertion === SERVICE_ASSERTION) {
		return { kind: "service", commonName: "token-consumer", sub: null };
	}
	throw new Error("Invalid assertion");
};

function securedRequest(url: string, assertion: string, init: RequestInit = {}): Request {
	const headers = new Headers(init.headers);
	headers.set("Cf-Access-Jwt-Assertion", assertion);
	return new Request(url, { ...init, headers });
}

function assertSecurityHeaders(response: Response): void {
	assert.equal(response.headers.get("cache-control"), "no-store");
	assert.equal(response.headers.get("x-content-type-options"), "nosniff");
	assert.equal(response.headers.get("referrer-policy"), "no-referrer");
	assert.match(response.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
}

test("OAuth state generation comparison rejects altered values", () => {
	assert.equal(statesMatch("same-state", "same-state"), true);
	assert.equal(statesMatch("same-state", "same-statf"), false);
	assert.equal(statesMatch("short", "longer"), false);
});

test("request origin must be HTTPS except for loopback development", () => {
	const productionRequest = new Request("https://facebook-worker.example/admin?view=status");
	assert.equal(
		getPublicBaseUrl(productionRequest).toString(),
		"https://facebook-worker.example/",
	);
	assert.equal(getRedirectUri(productionRequest), "https://facebook-worker.example/callback");
	assert.throws(() => getPublicBaseUrl(new Request("http://facebook-worker.example/")));
	assert.equal(
		getPublicBaseUrl(new Request("http://localhost:8787/admin")).toString(),
		"http://localhost:8787/",
	);
});

test("protected routes require Access and interactive routes reject services", async () => {
	const worker = createWorker({ verifyAccess });
	const env = workerEnv();

	const missing = await worker.fetch!(
		new Request("https://facebook-worker.example/"),
		env,
		{} as ExecutionContext,
	);
	assert.equal(missing.status, 401);
	assertSecurityHeaders(missing);

	const invalid = await worker.fetch!(
		securedRequest("https://facebook-worker.example/", "invalid"),
		env,
		{} as ExecutionContext,
	);
	assert.equal(invalid.status, 403);

	const serviceOnPage = await worker.fetch!(
		securedRequest("https://facebook-worker.example/", SERVICE_ASSERTION),
		env,
		{} as ExecutionContext,
	);
	assert.equal(serviceOnPage.status, 403);

	const userOnPage = await worker.fetch!(
		securedRequest("https://facebook-worker.example/", USER_ASSERTION),
		env,
		{} as ExecutionContext,
	);
	assert.equal(userOnPage.status, 200);
});

test("administration page shows full token and expiry fields", async () => {
	const token = "SECRET_FACEBOOK_TOKEN_123456789";
	const kv = memoryKv({
		accessToken: token,
		updatedAt: "2026-07-24T10:00:00.000Z",
		expiresAt: "2099-07-24T10:00:00.000Z",
	});
	const worker = createWorker();
	const response = await worker.fetch!(
		new Request("http://localhost:9999/"),
		workerEnv({}, kv),
		{} as ExecutionContext,
	);
	const html = await response.text();

	assert.equal(response.status, 200);
	assert.match(
		html,
		/<dt>Token<\/dt>\s*<dd><input class="token-field" type="text" readonly value="SECRET_FACEBOOK_TOKEN_123456789"><\/dd>/,
	);
	assert.match(
		html,
		/<dt>Updated<\/dt>\s*<dd><input class="token-field" type="text" readonly value="2026-07-24T10:00:00\.000Z"><\/dd>/,
	);
	assert.match(
		html,
		/<dt>Expires<\/dt>\s*<dd><input class="token-field" type="text" readonly value="2099-07-24T10:00:00\.000Z"><\/dd>/,
	);
	assert.match(html, /2026-07-24T10:00:00\.000Z/);
	assert.match(html, /2099-07-24T10:00:00\.000Z/);
	assert.match(html, /<dt>Remaining<\/dt>\s*<dd>[^<]*minute/);
	assert.equal(html.includes("Token stored"), false);
	assert.equal(html.includes("<dt>Expired</dt>"), false);
	assert.match(html, /http:\/\/localhost:9999\/callback/);
	assertSecurityHeaders(response);
});

test("administration page shows expired token state as Expired", async () => {
	const token = "SECRET_FACEBOOK_TOKEN_123456789";
	const kv = memoryKv({
		accessToken: token,
		updatedAt: "2026-07-24T10:00:00.000Z",
		expiresAt: "2026-07-24T09:59:00.000Z",
	});
	const worker = createWorker();
	const response = await worker.fetch!(
		new Request("http://localhost:9999/"),
		workerEnv({}, kv),
		{} as ExecutionContext,
	);
	const html = await response.text();

	assert.equal(response.status, 200);
	assert.match(html, /<dt>Remaining<\/dt>\s*<dd>Expired<\/dd>/);
	assert.equal(html.includes("No token"), false);
	assertSecurityHeaders(response);
});

test("authentication redirect uses the request origin", async () => {
	const worker = createWorker();
	const response = await worker.fetch!(
		new Request("http://localhost:9999/authenticate", { method: "POST" }),
		workerEnv(),
		{} as ExecutionContext,
	);

	assert.equal(response.status, 302);
	const authorizationUrl = new URL(response.headers.get("location") ?? "");
	assert.equal(
		authorizationUrl.searchParams.get("redirect_uri"),
		"http://localhost:9999/callback",
	);
	assert.match(response.headers.get("set-cookie") ?? "", /facebook_oauth_state=[a-f0-9]{64}/);
	assertSecurityHeaders(response);
});

test("callback rejects missing and invalid OAuth state", async () => {
	const worker = createWorker();
	const env = workerEnv();

	const missing = await worker.fetch!(
		new Request("http://localhost:9999/callback?code=code"),
		env,
		{} as ExecutionContext,
	);
	assert.equal(missing.status, 400);

	const invalid = await worker.fetch!(
		new Request("http://localhost:9999/callback?code=code&state=received", {
			headers: { cookie: "facebook_oauth_state=expected" },
		}),
		env,
		{} as ExecutionContext,
	);
	assert.equal(invalid.status, 400);
	assertSecurityHeaders(invalid);
});

test("callback sends token exchange values in a form body and stores the token", async (context) => {
	const originalFetch = globalThis.fetch;
	const requests: Array<{ url: string; init?: RequestInit }> = [];
	globalThis.fetch = async (input, init) => {
		requests.push({ url: String(input), init });
		if (String(input).endsWith("/oauth/access_token")) {
			return Response.json({
				access_token: "facebook-token-value",
				expires_in: 3600,
			});
		}
		return Response.json({
			data: { data_access_expires_at: 4_102_444_800, expires_at: 1_700_000_000 },
		});
	};
	context.after(() => {
		globalThis.fetch = originalFetch;
	});

	const kv = memoryKv();
	const worker = createWorker();
	const response = await worker.fetch!(
		new Request("http://localhost:9999/callback?code=authorization-code&state=matching-state", {
			headers: { cookie: "facebook_oauth_state=matching-state" },
		}),
		workerEnv({}, kv),
		{} as ExecutionContext,
	);

	assert.equal(response.status, 302);
	assert.equal(response.headers.get("location"), "http://localhost:9999/");
	assert.equal(requests.length, 2);
	assert.equal(requests[0].url, "https://graph.facebook.com/v25.0/oauth/access_token");
	assert.equal(requests[0].init?.method, "POST");
	assert.equal(
		new Headers(requests[0].init?.headers).get("content-type"),
		"application/x-www-form-urlencoded",
	);
	const body = new URLSearchParams(String(requests[0].init?.body));
	assert.equal(body.get("client_id"), "test-app-id");
	assert.equal(body.get("client_secret"), "test-app-secret");
	assert.equal(body.get("code"), "authorization-code");
	assert.equal(body.get("redirect_uri"), "http://localhost:9999/callback");
	assert.equal(requests[0].url.includes("test-app-secret"), false);
	assert.equal(requests[0].url.includes("authorization-code"), false);
	assert.equal(requests[1].url, "https://graph.facebook.com/v25.0/debug_token");
	assert.equal(requests[1].init?.method, "POST");
	assert.equal(
		new Headers(requests[1].init?.headers).get("content-type"),
		"application/x-www-form-urlencoded",
	);
	assert.equal(
		new URLSearchParams(String(requests[1].init?.body)).get("input_token"),
		"facebook-token-value",
	);
	assert.equal(kv.read()?.expiresAt, new Date(4_102_444_800 * 1000).toISOString());
	assert.equal(kv.read()?.dataAccessExpiresAt, new Date(4_102_444_800 * 1000).toISOString());
	assert.equal(kv.read()?.accessToken, "facebook-token-value");
	assertSecurityHeaders(response);
});

test("token debugging also keeps Facebook tokens and app credentials out of URLs", async (context) => {
	const originalFetch = globalThis.fetch;
	const requests: Array<{ url: string; init?: RequestInit }> = [];
	globalThis.fetch = async (input, init) => {
		requests.push({ url: String(input), init });
		if (String(input).endsWith("/oauth/access_token")) {
			return Response.json({ access_token: "facebook-token-value" });
		}
		return Response.json({ data: { expires_at: 4_102_444_800 } });
	};
	context.after(() => {
		globalThis.fetch = originalFetch;
	});

	const worker = createWorker();
	const response = await worker.fetch!(
		new Request("http://localhost:9999/callback?code=authorization-code&state=matching-state", {
			headers: { cookie: "facebook_oauth_state=matching-state" },
		}),
		workerEnv(),
		{} as ExecutionContext,
	);

	assert.equal(response.status, 302);
	assert.equal(requests.length, 2);
	assert.equal(requests[1].url, "https://graph.facebook.com/v25.0/debug_token");
	const debugBody = new URLSearchParams(String(requests[1].init?.body));
	assert.equal(debugBody.get("input_token"), "facebook-token-value");
	assert.equal(debugBody.get("access_token"), "test-app-id|test-app-secret");
	assert.equal(requests[1].url.includes("facebook-token-value"), false);
	assert.equal(requests[1].url.includes("test-app-secret"), false);
});

test("callback defaults token expiry to 90 days when Facebook returns no expiry values", async (context) => {
	const originalFetch = globalThis.fetch;
	const requests: Array<{ url: string; init?: RequestInit }> = [];
	const before = Date.now();
	const expectedMin = before + 90 * 24 * 60 * 60 * 1000 - 5000;
	const expectedMax = before + 90 * 24 * 60 * 60 * 1000 + 5000;

	globalThis.fetch = async (input, init) => {
		requests.push({ url: String(input), init });
		if (String(input).endsWith("/oauth/access_token")) {
			return Response.json({ access_token: "facebook-token-value" });
		}
		return Response.json({ data: {} });
	};
	context.after(() => {
		globalThis.fetch = originalFetch;
	});

	const kv = memoryKv();
	const worker = createWorker();
	const response = await worker.fetch!(
		new Request("http://localhost:9999/callback?code=authorization-code&state=matching-state", {
			headers: { cookie: "facebook_oauth_state=matching-state" },
		}),
		workerEnv({}, kv),
		{} as ExecutionContext,
	);

	assert.equal(response.status, 302);
	assert.equal(requests.length, 2);
	const expiresAt = kv.read()?.expiresAt;
	assert.equal(typeof expiresAt, "string");
	const expiresAtMs = Date.parse(expiresAt);
	assert.ok(
		expiresAtMs >= expectedMin,
		`expiresAt (${expiresAt}) should be no earlier than 90-day min`,
	);
	assert.ok(
		expiresAtMs <= expectedMax,
		`expiresAt (${expiresAt}) should be no later than 90-day max`,
	);
	assert.equal(kv.read()?.dataAccessExpiresAt, null);
	assertSecurityHeaders(response);
});

test("Facebook callback errors are generic and do not expose upstream details", async () => {
	const worker = createWorker();
	const response = await worker.fetch!(
		new Request(
			"http://localhost:9999/callback?error=access_denied&error_description=sensitive-upstream-detail",
		),
		workerEnv(),
		{} as ExecutionContext,
	);
	const body = await response.text();

	assert.equal(response.status, 400);
	assert.equal(body, "Facebook authorization failed.");
	assert.equal(body.includes("sensitive-upstream-detail"), false);
	assertSecurityHeaders(response);
});

test("failed token exchange logs only fixed safe metadata", async () => {
	const originalFetch = globalThis.fetch;
	const originalError = console.error;
	const originalInfo = console.info;
	const originalLog = console.log;
	const loggedValues: unknown[][] = [];
	const sensitiveValues = [
		"sensitive-authorization-code",
		"sensitive-access-token",
		"sensitive-upstream-description",
		"sensitive-app-secret",
	];

	globalThis.fetch = async () =>
		new Response(
			JSON.stringify({
				access_token: "sensitive-access-token",
				error: "OAuthException",
				error_description: "sensitive-upstream-description",
				credential: "sensitive-app-secret",
			}),
			{
				status: 400,
				statusText: "sensitive-upstream-description",
				headers: { "content-type": "application/json" },
			},
		);
	const capture = (...values: unknown[]) => {
		loggedValues.push(values);
	};
	console.error = capture;
	console.info = capture;
	console.log = capture;

	try {
		const worker = createWorker();
		const response = await worker.fetch!(
			new Request(
				"http://localhost:9999/callback?code=sensitive-authorization-code&state=matching-state",
				{
					headers: { cookie: "facebook_oauth_state=matching-state" },
				},
			),
			workerEnv({ APP_SECRET: "sensitive-app-secret" }),
			{} as ExecutionContext,
		);
		const responseBody = await response.text();

		assert.equal(response.status, 502);
		assert.equal(responseBody, "Unable to exchange Facebook token.");
		assertSecurityHeaders(response);
	} finally {
		globalThis.fetch = originalFetch;
		console.error = originalError;
		console.info = originalInfo;
		console.log = originalLog;
	}

	assert.deepEqual(loggedValues[0], [
		{
			event: "facebook_token_exchange",
			outcome: "failure",
			failureType: "upstream_rejected",
			httpStatus: 400,
		},
	]);
	const serializedLogs = JSON.stringify(loggedValues);
	for (const sensitiveValue of sensitiveValues) {
		assert.equal(serializedLogs.includes(sensitiveValue), false);
	}
});

test("token expiry lookup failures do not log tokens or upstream error details", async () => {
	const originalFetch = globalThis.fetch;
	const originalError = console.error;
	const originalInfo = console.info;
	const originalLog = console.log;
	const loggedValues: unknown[][] = [];
	let requestCount = 0;

	globalThis.fetch = async () => {
		requestCount += 1;
		if (requestCount === 1) {
			return Response.json({
				access_token: "sensitive-facebook-token",
			});
		}
		throw new Error(
			"upstream failure containing sensitive-facebook-token and sensitive-app-secret",
		);
	};
	const capture = (...values: unknown[]) => {
		loggedValues.push(values);
	};
	console.error = capture;
	console.info = capture;
	console.log = capture;

	try {
		const worker = createWorker();
		const response = await worker.fetch!(
			new Request(
				"http://localhost:9999/callback?code=sensitive-authorization-code&state=matching-state",
				{
					headers: { cookie: "facebook_oauth_state=matching-state" },
				},
			),
			workerEnv({ APP_SECRET: "sensitive-app-secret" }),
			{} as ExecutionContext,
		);

		assert.equal(response.status, 302);
	} finally {
		globalThis.fetch = originalFetch;
		console.error = originalError;
		console.info = originalInfo;
		console.log = originalLog;
	}

	assert.ok(
		loggedValues.some(
			(values) =>
				JSON.stringify(values) ===
				JSON.stringify([
					{
						event: "facebook_token_expiry_lookup",
						outcome: "failure",
						failureType: "debug_request_failed",
					},
				]),
		),
	);
	const serializedLogs = JSON.stringify(loggedValues);
	assert.equal(serializedLogs.includes("sensitive-facebook-token"), false);
	assert.equal(serializedLogs.includes("sensitive-authorization-code"), false);
	assert.equal(serializedLogs.includes("sensitive-app-secret"), false);
	assert.equal(serializedLogs.includes("upstream failure"), false);
});

test("token persistence failures do not log stored values or error details", async () => {
	const originalFetch = globalThis.fetch;
	const originalError = console.error;
	const originalInfo = console.info;
	const originalLog = console.log;
	const loggedValues: unknown[][] = [];

	globalThis.fetch = async (input) => {
		if (String(input).endsWith("/oauth/access_token")) {
			return Response.json({
				access_token: "sensitive-facebook-token",
				expires_in: 3600,
			});
		}
		return Response.json({ data: { expires_at: 4_102_444_800 } });
	};
	const capture = (...values: unknown[]) => {
		loggedValues.push(values);
	};
	console.error = capture;
	console.info = capture;
	console.log = capture;

	const rejectingKv = {
		async get() {
			return null;
		},
		async put() {
			throw new Error(
				"storage failure containing sensitive-facebook-token and sensitive-storage-detail",
			);
		},
	} as unknown as KVNamespace;

	try {
		const worker = createWorker();
		const response = await worker.fetch!(
			new Request(
				"http://localhost:9999/callback?code=sensitive-authorization-code&state=matching-state",
				{
					headers: { cookie: "facebook_oauth_state=matching-state" },
				},
			),
			workerEnv({ FACEBOOK_AUTH: rejectingKv }),
			{} as ExecutionContext,
		);
		const responseBody = await response.text();

		assert.equal(response.status, 502);
		assert.equal(responseBody, "Unable to store Facebook token.");
	} finally {
		globalThis.fetch = originalFetch;
		console.error = originalError;
		console.info = originalInfo;
		console.log = originalLog;
	}

	assert.ok(
		loggedValues.some(
			(values) =>
				JSON.stringify(values) ===
				JSON.stringify([
					{
						event: "facebook_token_persistence",
						outcome: "failure",
						failureType: "storage_write_failed",
					},
				]),
		),
	);
	const serializedLogs = JSON.stringify(loggedValues);
	assert.equal(serializedLogs.includes("sensitive-facebook-token"), false);
	assert.equal(serializedLogs.includes("sensitive-authorization-code"), false);
	assert.equal(serializedLogs.includes("sensitive-storage-detail"), false);
});

test("token API requires Access plus API key and reports missing, expired, and valid states", async () => {
	const worker = createWorker({ verifyAccess });
	const baseEnv = workerEnv();
	const apiUrl = "https://facebook-worker.example/api/token";

	const noAccess = await worker.fetch!(
		new Request(apiUrl, {
			headers: { authorization: "Bearer test-token-api-key" },
		}),
		baseEnv,
		{} as ExecutionContext,
	);
	assert.equal(noAccess.status, 401);

	const noApiKey = await worker.fetch!(
		securedRequest(apiUrl, SERVICE_ASSERTION),
		baseEnv,
		{} as ExecutionContext,
	);
	assert.equal(noApiKey.status, 401);

	const invalidApiKey = await worker.fetch!(
		securedRequest(apiUrl, SERVICE_ASSERTION, {
			headers: { authorization: "Bearer wrong-key" },
		}),
		baseEnv,
		{} as ExecutionContext,
	);
	assert.equal(invalidApiKey.status, 401);

	const missingToken = await worker.fetch!(
		securedRequest(apiUrl, SERVICE_ASSERTION, {
			headers: { authorization: "Bearer test-token-api-key" },
		}),
		baseEnv,
		{} as ExecutionContext,
	);
	assert.equal(missingToken.status, 404);

	const expiredKv = memoryKv({
		accessToken: "expired-facebook-token",
		expiresAt: "2020-01-01T00:00:00.000Z",
		updatedAt: "2019-12-01T00:00:00.000Z",
	});
	const expired = await worker.fetch!(
		securedRequest(apiUrl, SERVICE_ASSERTION, {
			headers: { authorization: "Bearer test-token-api-key" },
		}),
		workerEnv({}, expiredKv),
		{} as ExecutionContext,
	);
	assert.equal(expired.status, 410);
	assert.deepEqual(await expired.json(), {
		error: "The stored Facebook access token has expired.",
		expiresAt: "2020-01-01T00:00:00.000Z",
		updatedAt: "2019-12-01T00:00:00.000Z",
		expired: true,
	});

	const validKv = memoryKv({
		accessToken: "valid-facebook-token",
		expiresAt: "2099-01-01T00:00:00.000Z",
		updatedAt: "2026-07-24T00:00:00.000Z",
	});
	const valid = await worker.fetch!(
		securedRequest(apiUrl, SERVICE_ASSERTION, {
			headers: { authorization: "Bearer test-token-api-key" },
		}),
		workerEnv({}, validKv),
		{} as ExecutionContext,
	);
	assert.equal(valid.status, 200);
	assert.deepEqual(await valid.json(), {
		accessToken: "valid-facebook-token",
		expiresAt: "2099-01-01T00:00:00.000Z",
		updatedAt: "2026-07-24T00:00:00.000Z",
		expired: false,
	});
	assertSecurityHeaders(valid);
});

test("structured request logs contain only safe fixed metadata", async () => {
	const originalError = console.error;
	const events: unknown[] = [];
	console.error = (event: unknown) => {
		events.push(event);
	};

	try {
		const worker = createWorker();
		const response = await worker.fetch!(
			new Request(
				"http://localhost:9999/callback?error=access_denied&error_description=secret-value",
			),
			workerEnv({
				APP_SECRET: "secret-app-value",
				TOKEN_API_KEY: "secret-api-value",
			}),
			{} as ExecutionContext,
		);
		assert.equal(response.status, 400);
	} finally {
		console.error = originalError;
	}

	assert.equal(events.length, 1);
	assert.deepEqual(Object.keys(events[0] as object).sort(), [
		"durationMs",
		"errorCategory",
		"event",
		"operation",
		"status",
	]);
	const serialized = JSON.stringify(events);
	assert.equal(serialized.includes("secret-value"), false);
	assert.equal(serialized.includes("secret-app-value"), false);
	assert.equal(serialized.includes("secret-api-value"), false);
});
