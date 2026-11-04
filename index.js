import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { registerSandboxBackend } from "openclaw/plugin-sdk/sandbox";
import {
	LOCAL_USER_SANDBOX_BACKEND_ID,
	createLocalUserSandboxBackendFactory,
	createLocalUserSandboxBackendManager,
	resolveLocalUserSandboxConfig,
	resolveLocalUserSandboxWorkdir
} from "./src/backend.js";

export default definePluginEntry({
	id: "local-user",
	name: "Local User Sandbox",
	description: "Sandbox backend that runs exec and file tools on the Gateway host as an unprivileged local user",
	register(api) {
		if (api.registrationMode !== "full") return;
		const config = resolveLocalUserSandboxConfig(api.pluginConfig);
		const unregister = registerSandboxBackend(LOCAL_USER_SANDBOX_BACKEND_ID, {
			factory: createLocalUserSandboxBackendFactory(config),
			manager: createLocalUserSandboxBackendManager(config),
			resolveWorkdir: resolveLocalUserSandboxWorkdir
		});
		api.lifecycle.registerRuntimeLifecycle({
			id: "local-user-cleanup",
			cleanup: ({ reason, sessionKey, runId }) => {
				if (sessionKey !== undefined || runId !== undefined) return;
				if (reason === "disable" || reason === "restart") unregister();
			}
		});
	}
});
