import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

import { assertPublicConfigurationIsSanitized } from "../scripts/check-public-config.mjs";

async function withFixture(files: Record<string, string>, fn: (basePath: string) => Promise<void>) {
	const directory = await mkdtemp(join(tmpdir(), "cloudflare-facebook-public-config-"));
	try {
		await Promise.all(
			Object.entries(files).map(([path, contents]) =>
				writeFile(join(directory, path), `${contents}\n`),
			),
		);
		await fn(directory);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
}

function fixturePaths(directory: string) {
	return {
		wranglerPath: join(directory, "wrangler.toml"),
		gitignorePath: join(directory, ".gitignore"),
		packageJsonPath: join(directory, "package.json"),
		workerTypesPath: join(directory, "worker-configuration.d.ts"),
	};
}

const validWranglerConfig = `
name = "cloudflare-facebook"
main = "src/index.ts"
compatibility_date = "2026-06-07"
keep_vars = true

[[kv_namespaces]]
binding = "FACEBOOK_AUTH"
id = "replace-with-your-kv-namespace-id"

[observability]
enabled = true
`.trim();

const validGitignore = `
.dev.vars
.wrangler/
wrangler.production.toml
wrangler.generated.json
wrangler.*.toml
!wrangler.toml
`.trim();

const validPackageJson = JSON.stringify(
	{
		scripts: {
			"cloudflare:upload":
				"npm run cloudflare:config && wrangler versions upload --config wrangler.generated.json",
			"cloudflare:deploy":
				"npm run cloudflare:config && wrangler deploy --config wrangler.generated.json",
		},
	},
	null,
	2,
);

test("public config checker passes when configuration is sanitized", async () => {
	await withFixture(
		{
			"wrangler.toml": validWranglerConfig,
			".gitignore": validGitignore,
			"package.json": validPackageJson,
			"worker-configuration.d.ts":
				"interface Env {\n\treadonly TEAM_DOMAIN: string;\n\treadonly POLICY_AUD: string;\n\treadonly APP_ID: string;\n}\n",
		},
		async (directory) => {
			const paths = fixturePaths(directory);
			await assertPublicConfigurationIsSanitized(paths);
		},
	);
});

test("public config checker rejects production account IDs", async () => {
	await withFixture(
		{
			"wrangler.toml": `${validWranglerConfig}\naccount_id = "replace-with-your-cloudflare-account-id"`,
			".gitignore": validGitignore,
			"package.json": validPackageJson,
			"worker-configuration.d.ts": "interface Env {\n\treadonly TEAM_DOMAIN: string;\n}\n",
		},
		async (directory) => {
			const paths = fixturePaths(directory);
			await assert.rejects(
				assertPublicConfigurationIsSanitized(paths),
				/wrangler\.toml must not contain account_id/,
			);
		},
	);
});

test("public config checker rejects a missing top-level keep_vars setting", async () => {
	await withFixture(
		{
			"wrangler.toml": validWranglerConfig.replace("keep_vars = true\n", ""),
			".gitignore": validGitignore,
			"package.json": validPackageJson,
			"worker-configuration.d.ts": "interface Env {\n\treadonly TEAM_DOMAIN: string;\n}\n",
		},
		async (directory) => {
			const paths = fixturePaths(directory);
			await assert.rejects(
				assertPublicConfigurationIsSanitized(paths),
				/wrangler\.toml must set top-level keep_vars = true/,
			);
		},
	);
});

test("public config checker rejects a public vars block", async () => {
	await withFixture(
		{
			"wrangler.toml": `${validWranglerConfig}\n\n[vars]\nAPP_ID = "public-value"`,
			".gitignore": validGitignore,
			"package.json": validPackageJson,
			"worker-configuration.d.ts": "interface Env {\n\treadonly TEAM_DOMAIN: string;\n}\n",
		},
		async (directory) => {
			const paths = fixturePaths(directory);
			await assert.rejects(
				assertPublicConfigurationIsSanitized(paths),
				/wrangler\.toml must not contain a \[vars\] block/,
			);
		},
	);
});

test("public config checker rejects scripts that are not using generated deployment config", async () => {
	await withFixture(
		{
			"wrangler.toml": validWranglerConfig,
			".gitignore": validGitignore,
			"package.json": JSON.stringify(
				{
					scripts: {
						"cloudflare:upload": "wrangler deploy --config wrangler.toml",
						"cloudflare:deploy": "wrangler deploy --config wrangler.production.toml",
					},
				},
				null,
				2,
			),
			"worker-configuration.d.ts": "interface Env {\n\treadonly TEAM_DOMAIN: string;\n}\n",
		},
		async (directory) => {
			const paths = fixturePaths(directory);
			await assert.rejects(
				assertPublicConfigurationIsSanitized(paths),
				/Cloudflare uploads must use wrangler\.generated\.json/,
			);
		},
	);
});

test("public config checker fails when worker types contain literal production-style Access values", async () => {
	await withFixture(
		{
			"wrangler.toml": validWranglerConfig,
			".gitignore": validGitignore,
			"package.json": validPackageJson,
			"worker-configuration.d.ts": `interface Env {\n\treadonly TEAM_DOMAIN: "https://prod.cloudflareaccess.com";\n}`,
		},
		async (directory) => {
			const paths = fixturePaths(directory);
			await assert.rejects(
				assertPublicConfigurationIsSanitized(paths),
				/Worker types must not contain literal Access team domains/,
			);
		},
	);
});
