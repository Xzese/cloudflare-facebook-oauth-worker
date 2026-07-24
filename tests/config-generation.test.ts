import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

import {
	buildCloudflareConfig,
	writeCloudflareConfig,
} from "../scripts/generate-cloudflare-config.mjs";

test("Cloudflare generated config preserves dashboard values and required deployment metadata", () => {
	const namespaceId = "a".repeat(32);
	const config = buildCloudflareConfig({
		FACEBOOK_AUTH_KV_NAMESPACE_ID: namespaceId,
	});

	assert.equal(config.keep_vars, true);
	assert.equal("vars" in config, false);
	assert.deepEqual(config.secrets.required, ["APP_SECRET", "TOKEN_API_KEY"]);
	assert.deepEqual(config.kv_namespaces, [{ binding: "FACEBOOK_AUTH", id: namespaceId }]);
	assert.equal(config.observability.enabled, true);
	assert.equal(config.name, "cloudflare-facebook");
});

test("Cloudflare generated config rejects missing or malformed namespace IDs", () => {
	assert.throws(
		() => buildCloudflareConfig({}),
		/FACEBOOK_AUTH_KV_NAMESPACE_ID must be configured as a private Cloudflare build variable/,
	);
	assert.throws(
		() => buildCloudflareConfig({ FACEBOOK_AUTH_KV_NAMESPACE_ID: "not-hex" }),
		/32-character hexadecimal namespace ID/,
	);
});

test("generated Cloudflare config is written with 0600 permissions and no vars block", async (context) => {
	const namespaceId = "b".repeat(32);
	const directory = await mkdtemp(join(tmpdir(), "cloudflare-facebook-config-"));
	context.after(() => rm(directory, { recursive: true, force: true }));
	const outputPath = join(directory, "wrangler.generated.json");

	await writeFile(outputPath, "{}\n", { mode: 0o644 });
	await chmod(outputPath, 0o644);
	await writeCloudflareConfig({ FACEBOOK_AUTH_KV_NAMESPACE_ID: namespaceId }, outputPath);

	const config = JSON.parse(await readFile(outputPath, "utf8"));
	const mode = (await stat(outputPath)).mode & 0o777;

	assert.equal(config.keep_vars, true);
	assert.equal(config.kv_namespaces[0].id, namespaceId);
	assert.equal("vars" in config, false);
	assert.equal(mode, 0o600);
});
