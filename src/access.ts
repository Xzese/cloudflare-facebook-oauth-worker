import { createRemoteJWKSet, jwtVerify } from "jose";

export interface AccessEnv {
	TEAM_DOMAIN: string;
	POLICY_AUD: string;
}

export interface UserAccessIdentity {
	kind: "user";
	email: string;
	sub: string;
}

export interface ServiceAccessIdentity {
	kind: "service";
	commonName: string;
	sub: string | null;
}

export type AccessIdentity = UserAccessIdentity | ServiceAccessIdentity;
export type AccessIdentityRequirement = "human" | "user-or-service";
export type AccessVerifier = (assertion: string, env: AccessEnv) => Promise<AccessIdentity>;

type VerificationKey = Parameters<typeof jwtVerify>[1];

let cachedTeamDomain: string | undefined;
let cachedJwks: ReturnType<typeof createRemoteJWKSet> | undefined;

export function isLoopbackHostname(hostname: string): boolean {
	return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

export function isLocalDevelopment(request: Request): boolean {
	return isLoopbackHostname(new URL(request.url).hostname);
}

export function getAccessTeamDomain(env: AccessEnv): string {
	if (!env.TEAM_DOMAIN || !env.POLICY_AUD) {
		throw new Error("Cloudflare Access is not configured.");
	}

	let teamUrl: URL;
	try {
		teamUrl = new URL(env.TEAM_DOMAIN);
	} catch {
		throw new Error("Cloudflare Access is not configured.");
	}

	if (
		teamUrl.protocol !== "https:" ||
		teamUrl.username ||
		teamUrl.password ||
		teamUrl.pathname !== "/" ||
		teamUrl.search ||
		teamUrl.hash
	) {
		throw new Error("Cloudflare Access is not configured.");
	}

	return teamUrl.origin;
}

function nonEmptyClaim(value: unknown): string | null {
	return typeof value === "string" && value.trim() ? value : null;
}

export async function verifyAccessJwt(
	assertion: string,
	env: AccessEnv,
	verificationKey?: VerificationKey,
): Promise<AccessIdentity> {
	const issuer = getAccessTeamDomain(env);

	let key = verificationKey;
	if (!key) {
		if (!cachedJwks || cachedTeamDomain !== issuer) {
			cachedTeamDomain = issuer;
			cachedJwks = createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`));
		}
		key = cachedJwks;
	}

	const { payload } = await jwtVerify(assertion, key, {
		issuer,
		audience: env.POLICY_AUD,
	});

	const email = nonEmptyClaim(payload.email);
	const subject = nonEmptyClaim(payload.sub);
	if (email && subject) {
		return { kind: "user", email, sub: subject };
	}

	const commonName = nonEmptyClaim(payload.common_name);
	if (commonName) {
		return {
			kind: "service",
			commonName,
			sub: subject,
		};
	}

	throw new Error("Cloudflare Access assertion has no usable identity.");
}

export async function accessRejection(
	request: Request,
	env: AccessEnv,
	requirement: AccessIdentityRequirement,
	verify: AccessVerifier = verifyAccessJwt,
): Promise<Response | undefined> {
	if (isLocalDevelopment(request)) {
		return undefined;
	}

	const assertion = request.headers.get("Cf-Access-Jwt-Assertion");
	if (!assertion) {
		return new Response("Unauthorized", { status: 401 });
	}

	try {
		const identity = await verify(assertion, env);
		if (requirement === "human" && identity.kind !== "user") {
			return new Response("Forbidden", { status: 403 });
		}
		return undefined;
	} catch {
		return new Response("Forbidden", { status: 403 });
	}
}
