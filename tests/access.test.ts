import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPair, SignJWT } from "jose";

import {
	accessRejection,
	isLocalDevelopment,
	verifyAccessJwt,
	type AccessEnv,
} from "../src/access.ts";

const ISSUER = "https://example.cloudflareaccess.com";
const AUDIENCE = "example-access-audience";

function accessEnv(values: Partial<AccessEnv> = {}): AccessEnv {
	return {
		POLICY_AUD: AUDIENCE,
		TEAM_DOMAIN: ISSUER,
		...values,
	};
}

async function assertion(
	privateKey: CryptoKey,
	claims: Record<string, unknown>,
	values: { issuer?: string; audience?: string } = {},
): Promise<string> {
	return new SignJWT(claims)
		.setProtectedHeader({ alg: "RS256", kid: "test-key" })
		.setIssuer(values.issuer ?? ISSUER)
		.setAudience(values.audience ?? AUDIENCE)
		.setIssuedAt()
		.setExpirationTime("5m")
		.sign(privateKey);
}

test("local Access bypass is restricted to exact loopback hostnames", () => {
	assert.equal(isLocalDevelopment(new Request("http://localhost:8787/")), true);
	assert.equal(isLocalDevelopment(new Request("http://127.0.0.1:8787/")), true);
	assert.equal(isLocalDevelopment(new Request("http://[::1]:8787/")), true);
	assert.equal(isLocalDevelopment(new Request("http://localhost.:8787/")), false);
	assert.equal(isLocalDevelopment(new Request("http://127.0.0.2:8787/")), false);
});

test("Access rejects missing and invalid assertions", async () => {
	const missing = await accessRejection(
		new Request("https://worker.example/"),
		accessEnv(),
		"human",
	);
	assert.equal(missing?.status, 401);

	const invalid = await accessRejection(
		new Request("https://worker.example/", {
			headers: { "Cf-Access-Jwt-Assertion": "invalid" },
		}),
		accessEnv(),
		"human",
		async () => {
			throw new Error("invalid signature");
		},
	);
	assert.equal(invalid?.status, 403);
});

test("Access JWT verification validates signature, issuer, and audience", async () => {
	const trusted = await generateKeyPair("RS256");
	const untrusted = await generateKeyPair("RS256");
	const claims = { email: "person@example.com", sub: "user-123" };

	await assert.rejects(
		verifyAccessJwt(
			await assertion(untrusted.privateKey, claims),
			accessEnv(),
			trusted.publicKey,
		),
	);
	await assert.rejects(
		verifyAccessJwt(
			await assertion(trusted.privateKey, claims, {
				issuer: "https://other.cloudflareaccess.com",
			}),
			accessEnv(),
			trusted.publicKey,
		),
	);
	await assert.rejects(
		verifyAccessJwt(
			await assertion(trusted.privateKey, claims, {
				audience: "wrong-audience",
			}),
			accessEnv(),
			trusted.publicKey,
		),
	);
});

test("Access JWT verification accepts human and service identities", async () => {
	const trusted = await generateKeyPair("RS256");

	const user = await verifyAccessJwt(
		await assertion(trusted.privateKey, {
			email: "person@example.com",
			sub: "user-123",
		}),
		accessEnv(),
		trusted.publicKey,
	);
	assert.deepEqual(user, {
		kind: "user",
		email: "person@example.com",
		sub: "user-123",
	});

	const service = await verifyAccessJwt(
		await assertion(trusted.privateKey, {
			common_name: "token-consumer",
			sub: "",
		}),
		accessEnv(),
		trusted.publicKey,
	);
	assert.deepEqual(service, {
		kind: "service",
		commonName: "token-consumer",
		sub: null,
	});
});

test("interactive Access requires a human while token access allows a service", async () => {
	const request = new Request("https://worker.example/", {
		headers: { "Cf-Access-Jwt-Assertion": "service-assertion" },
	});
	const verifyService = async () =>
		({
			kind: "service",
			commonName: "token-consumer",
			sub: null,
		}) as const;

	assert.equal(
		(await accessRejection(request, accessEnv(), "human", verifyService))?.status,
		403,
	);
	assert.equal(
		await accessRejection(request, accessEnv(), "user-or-service", verifyService),
		undefined,
	);
});

test("Access fails closed when its issuer or audience is not configured", async () => {
	const trusted = await generateKeyPair("RS256");
	const token = await assertion(trusted.privateKey, {
		email: "person@example.com",
		sub: "user-123",
	});

	await assert.rejects(
		verifyAccessJwt(
			token,
			accessEnv({ TEAM_DOMAIN: "http://example.cloudflareaccess.com" }),
			trusted.publicKey,
		),
	);
	await assert.rejects(verifyAccessJwt(token, accessEnv({ POLICY_AUD: "" }), trusted.publicKey));
});
