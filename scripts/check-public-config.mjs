import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const placeholderAssertions = [
	{
		name: "FACEBOOK kv namespace placeholder",
		pattern: /^\s*id\s*=\s*"replace-with-your-kv-namespace-id"\s*$/m,
	},
];

const requiredGitignoreEntries = [
	{ name: ".dev.vars", entry: ".dev.vars" },
	{ name: ".wrangler cache", entry: ".wrangler/" },
	{ name: "wrangler production config", entry: "wrangler.production.toml" },
	{ name: "generated private config", entry: "wrangler.generated.json" },
	{ name: "generic prod wrangler ignore", entry: "wrangler.*.toml" },
	{ name: "public wrangler re-include", entry: "!wrangler.toml" },
];

function hasLine(contents, line) {
	return contents
		.split(/\r?\n/)
		.map((value) => value.trim())
		.includes(line);
}

function checkPlaceholderValues(wranglerConfig) {
	assert.doesNotMatch(
		wranglerConfig,
		/^\s*account_id\s*=/m,
		"wrangler.toml must not contain account_id",
	);
	assert.match(
		wranglerConfig.split(/^\s*\[/m, 1)[0],
		/^\s*keep_vars\s*=\s*true\s*$/m,
		"wrangler.toml must set top-level keep_vars = true",
	);
	assert.doesNotMatch(
		wranglerConfig,
		/^\s*\[vars\]\s*$/m,
		"wrangler.toml must not contain a [vars] block",
	);

	for (const { name, pattern } of placeholderAssertions) {
		assert.match(wranglerConfig, pattern, `wrangler.toml must keep ${name}`);
	}
}

function checkIgnoreRules(gitignoreContents) {
	for (const item of requiredGitignoreEntries) {
		assert.ok(hasLine(gitignoreContents, item.entry), `${item.name} must be ignored`);
	}
}

function checkCloudflareScripts(packageJson) {
	assert.match(
		packageJson.scripts?.["cloudflare:upload"] ?? "",
		/--config wrangler\.generated\.json$/,
		"Cloudflare uploads must use wrangler.generated.json",
	);
	assert.match(
		packageJson.scripts?.["cloudflare:deploy"] ?? "",
		/--config wrangler\.generated\.json$/,
		"Cloudflare deployments must use wrangler.generated.json",
	);
}

function checkWorkerTypeLiterals(workerTypesPath = "worker-configuration.d.ts") {
	if (!existsSync(workerTypesPath)) {
		return;
	}

	return readFile(workerTypesPath, "utf8").then((content) => {
		assert.doesNotMatch(
			content,
			/\bTEAM_DOMAIN:\s*["'][^"']+["']/,
			"Worker types must not contain literal Access team domains",
		);
		assert.doesNotMatch(
			content,
			/\bPOLICY_AUD:\s*["'][^"']+["']/,
			"Worker types must not contain literal Access audiences",
		);
		assert.doesNotMatch(
			content,
			/\bAPP_ID:\s*["'][^"']+["']/,
			"Worker types must not contain literal Facebook app IDs",
		);
	});
}

export async function assertPublicConfigurationIsSanitized(
	paths = {
		wranglerPath: "wrangler.toml",
		gitignorePath: ".gitignore",
		packageJsonPath: "package.json",
		workerTypesPath: "worker-configuration.d.ts",
	},
) {
	const wranglerConfig = await readFile(paths.wranglerPath, "utf8");
	const gitignoreContents = await readFile(paths.gitignorePath, "utf8");
	const packageJson = JSON.parse(await readFile(paths.packageJsonPath, "utf8"));

	checkPlaceholderValues(wranglerConfig);
	checkIgnoreRules(gitignoreContents);
	checkCloudflareScripts(packageJson);

	await checkWorkerTypeLiterals(paths.workerTypesPath);

	console.log("Public configuration is sanitized.");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
	await assertPublicConfigurationIsSanitized();
}
