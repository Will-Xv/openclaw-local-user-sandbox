// Tools run on the Gateway host as an unprivileged uid. The shared remote-shell backend
// owns file operations, workdir validation, skills, and exec staging; this module only
// decides how one shell command is launched.
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import {
	createRemoteShellSandboxBackend,
	createRemoteShellSandboxSession,
	resolvePreferredOpenClawTmpDir
} from "openclaw/plugin-sdk/sandbox";

const execFileAsync = promisify(execFile);

export const LOCAL_USER_SANDBOX_BACKEND_ID = "local-user";
const DEFAULT_UID = 10001;
const DEFAULT_HOME = "/data/.sandbox-home";
const DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin";

// Runs as the sandbox user: every probe of Gateway secrets must fail before tools are allowed.
// $1 = Gateway pid, $2 = workspace, $3... = host paths that must stay unreadable.
const SELF_TEST_SCRIPT = [
	"fail=0",
	"if cat \"/proc/$1/environ\" >/dev/null 2>&1; then echo \"Gateway process environment is readable\"; fail=1; fi",
	"if ! test -w \"$2\"; then echo \"workspace $2 is not writable\"; fail=1; fi",
	"shift 2",
	"for p in \"$@\"; do if ls \"$p\" >/dev/null 2>&1; then echo \"$p is readable\"; fail=1; fi; done",
	"exit $fail"
].join("\n");

export function resolveLocalUserSandboxConfig(raw) {
	const config = raw && typeof raw === "object" ? raw : {};
	const uid = Number.isInteger(config.uid) ? config.uid : DEFAULT_UID;
	const gid = Number.isInteger(config.gid) ? config.gid : uid;
	if (uid <= 0 || gid <= 0) throw new Error("local-user sandbox uid and gid must be non-zero.");
	const home = typeof config.home === "string" && config.home.trim() ? path.resolve(config.home.trim()) : DEFAULT_HOME;
	const pathEnv = typeof config.path === "string" && config.path.trim() ? config.path.trim() : DEFAULT_PATH;
	return { uid, gid, home, path: pathEnv };
}

function configLabel(config) {
	return `uid ${config.uid}:${config.gid}`;
}

function minimalEnv(config) {
	return { PATH: config.path, HOME: config.home, LANG: "C.UTF-8" };
}

// setpriv drops to the sandbox ids; env -i makes sure no Gateway variable survives the switch.
function asSandboxUser(config, argv) {
	return [
		"setpriv",
		`--reuid=${config.uid}`,
		`--regid=${config.gid}`,
		"--clear-groups",
		"--no-new-privs",
		"--",
		"env",
		"-i",
		`PATH=${config.path}`,
		`HOME=${config.home}`,
		"LANG=C.UTF-8",
		...argv
	];
}

function resolveStateDir() {
	return path.resolve(process.env.OPENCLAW_STATE_DIR || path.join(os.homedir(), ".openclaw"));
}

function isInside(root, candidate) {
	const relative = path.relative(root, candidate);
	return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

async function chownTree(dir, config) {
	// -P (default) never follows symlinks; chown -h changes the link itself.
	await execFileAsync("find", [
		dir,
		"(", "!", "-uid", String(config.uid), "-o", "!", "-gid", String(config.gid), ")",
		"-exec", "chown", "-h", `${config.uid}:${config.gid}`, "{}", "+"
	]);
}

// OpenClaw-owned host paths that hold config, credentials, pre-repair captures, or logs.
async function existingProtectedPaths(stateDir) {
	const candidates = [stateDir, `${stateDir}.update-captures`, resolvePreferredOpenClawTmpDir()];
	const existing = [];
	for (const candidate of candidates) {
		const stat = await fs.lstat(candidate).catch(() => undefined);
		if (stat?.isDirectory()) existing.push(path.resolve(candidate));
	}
	return existing;
}

// Only drops group/other access on root-owned directories; the root Gateway is unaffected.
async function tightenProtectedPaths(paths) {
	for (const dir of paths) {
		const stat = await fs.lstat(dir);
		if (stat.uid === 0 && (stat.mode & 0o077) !== 0) await fs.chmod(dir, stat.mode & 0o700);
	}
}

async function selfTest(config, workspaceDir, protectedPaths) {
	const [command, ...args] = asSandboxUser(config, [
		"/bin/sh", "-c", SELF_TEST_SCRIPT, "local-user-sandbox-self-test",
		String(process.pid), workspaceDir, ...protectedPaths
	]);
	try {
		await execFileAsync(command, args, { env: minimalEnv(config), cwd: config.home });
	} catch (error) {
		const detail = String(error?.stdout || "").trim() || String(error?.message || error);
		throw new Error(`local-user sandbox self-test failed: ${detail}`);
	}
}

async function prepareHost(config, workspaceDir, verified) {
	if (typeof process.getuid !== "function" || process.getuid() !== 0) {
		throw new Error("local-user sandbox needs the Gateway to run as root so it can switch tools to the sandbox uid.");
	}
	const stateDir = resolveStateDir();
	if (workspaceDir === "/" || isInside(stateDir, workspaceDir)) {
		throw new Error(`local-user sandbox cannot use ${workspaceDir}: it is inside the OpenClaw state directory. Use workspaceAccess "rw" or move agents.defaults.sandbox.workspaceRoot outside ${stateDir}.`);
	}
	if (isInside(stateDir, config.home)) {
		throw new Error(`local-user sandbox home ${config.home} must be outside the OpenClaw state directory ${stateDir}.`);
	}
	await fs.mkdir(config.home, { recursive: true, mode: 0o700 });
	await fs.chown(config.home, config.uid, config.gid);
	await fs.chmod(config.home, 0o700);
	// Files the Gateway writes as root (for example reset hooks) are handed over on each provision.
	await chownTree(workspaceDir, config);
	if (!verified.has(workspaceDir)) {
		const protectedPaths = await existingProtectedPaths(stateDir);
		await tightenProtectedPaths(protectedPaths);
		await selfTest(config, workspaceDir, protectedPaths);
		verified.add(workspaceDir);
	}
}

export function createLocalUserSandboxBackendFactory(config) {
	const verified = new Set();
	return async (params) => {
		if ((params.cfg.docker?.binds?.length ?? 0) > 0) {
			throw new Error("local-user sandbox backend does not support sandbox.docker.binds.");
		}
		const workspaceDir = path.resolve(params.workspaceDir);
		params.assertRuntimeCurrent?.();
		await prepareHost(config, workspaceDir, verified);
		params.assertRuntimeCurrent?.();
		const runtimeId = `local-user-${createHash("sha256").update(workspaceDir).digest("hex").slice(0, 16)}`;
		return createRemoteShellSandboxBackend(params, {
			backendId: LOCAL_USER_SANDBOX_BACKEND_ID,
			runtimeId,
			configLabel: configLabel(config),
			configLabelKind: "User",
			// The agent workspace itself is the sandbox workdir: nothing is seeded or copied back.
			preprovisionedWorkdir: { remoteWorkspaceDir: workspaceDir, runtimeId },
			createSession: async () =>
				createRemoteShellSandboxSession({
					assertCurrent: params.assertRuntimeCurrent,
					buildCommand: ({ remoteCommand }) => ({
						argv: asSandboxUser(config, ["/bin/sh", "-c", remoteCommand]),
						env: minimalEnv(config),
						cwd: workspaceDir
					})
				})
		});
	};
}

export function createLocalUserSandboxBackendManager(config) {
	const label = configLabel(config);
	return {
		async describeRuntime({ entry }) {
			return { running: true, actualConfigLabel: entry.image, configLabelMatch: entry.image === label };
		},
		async removeRuntime() {
			// The runtime is the agent's own workspace; recreate and prune must never delete it.
		}
	};
}

export function resolveLocalUserSandboxWorkdir(params) {
	return path.resolve(params.workspaceDir);
}
