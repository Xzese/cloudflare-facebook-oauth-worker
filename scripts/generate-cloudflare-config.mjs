import { chmod, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

export const generatedConfigPath = "wrangler.generated.json";

const namespaceIdEnvironmentVariable = "FACEBOOK_AUTH_KV_NAMESPACE_ID";
const namespaceIdPattern = /^[a-f0-9]{32}$/i;

export function buildCloudflareConfig(environment = process.env) {
	const kvNamespaceId = environment[namespaceIdEnvironmentVariable]?.trim();

	if (!kvNamespaceId) {
		throw new Error(
			`${namespaceIdEnvironmentVariable} must be configured as a private Cloudflare build variable`,
		);
	}

	if (!namespaceIdPattern.test(kvNamespaceId)) {
		throw new Error(
			`${namespaceIdEnvironmentVariable} must be a 32-character hexadecimal namespace ID`,
		);
	}

	return {
		$schema: "node_modules/wrangler/config-schema.json",
		name: "cloudflare-facebook",
		main: "src/index.ts",
		compatibility_date: "2026-06-07",
		keep_vars: true,
		secrets: {
			required: ["APP_SECRET", "TOKEN_API_KEY"],
		},
		kv_namespaces: [
			{
				binding: "FACEBOOK_AUTH",
				id: kvNamespaceId,
			},
		],
		observability: {
			enabled: true,
		},
	};
}

export async function writeCloudflareConfig(
	environment = process.env,
	outputPath = generatedConfigPath,
) {
	const config = buildCloudflareConfig(environment);
	await writeFile(outputPath, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
	await chmod(outputPath, 0o600);
	return outputPath;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
	const outputPath = await writeCloudflareConfig();
	console.log(`Generated private Cloudflare deployment configuration at ${outputPath}`);
}
