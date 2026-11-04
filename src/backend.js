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
// $1 = Gateway pid, $2 = workspace that must be writable (empty to skip), $3... = host paths that must stay unreadable.
const SELF_TEST_SCRIPT = [
	"fail=0",
	"if cat \"/proc/$1/environ\" >/dev/null 2>&1; then echo \"Gateway process environment is readable\"; fail=1; fi",
	"if [ -n \"$2\" ] && ! test -w \"$2\"; then echo \"workspace $2 is not writable\"; fail=1; fi",
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

// Paths that do not exist yet are compared as written.
async function realPath(p) {
	return fs.realpath(p).catch(() => path.resolve(p));
}

// OpenClaw-owned host paths that hold config, credentials, pre-repair captures, or logs.
async function protectedPaths(stateDir) {
	const candidates = [stateDir, `${stateDir}.update-captures`, resolvePreferredOpenClawTmpDir()];
	return Promise.all(candidates.map(realPath));
}

// A directory handed to the sandbox uid must not contain or sit inside a protected path, and every
// directory above it must be root-owned and not writable by others (sticky dirs such as /tmp are fine),
// so the sandbox user cannot swap it for a symlink once it has been checked.
async function assertSafeSandboxDir(label, dir, protectedReal) {
	const stat = await fs.lstat(dir).catch(() => undefined);
	if (stat && !stat.isDirectory()) throw new Error(`local-user sandbox ${label} ${dir} must be a directory, not a symlink or file.`);
	const real = await realPath(dir);
	if (real !== path.resolve(dir)) throw new Error(`local-user sandbox ${label} ${dir} resolves to ${real}; configure the real path.`);
	for (const p of protectedReal) {
		if (isInside(p, real) || isInside(real, p)) {
			throw new Error(`local-user sandbox ${label} ${dir} overlaps the protected OpenClaw path ${p}. Use a ${label} that neither contains nor sits inside the state, capture, or log directories.`);
		}
	}
	for (let parent = path.dirname(real); ; parent = path.dirname(parent)) {
		const parentStat = await fs.lstat(parent).catch(() => undefined);
		const sticky = parentStat && (parentStat.mode & 0o1000) !== 0;
		if (parentStat && (parentStat.uid !== 0 || ((parentStat.mode & 0o022) !== 0 && !sticky))) {
			throw new Error(`local-user sandbox ${label} ${dir}: ${parent} must be root-owned and not writable by group or others.`);
		}
		if (parent === path.dirname(parent)) break;
	}
	return real;
}

// find -P never follows symlinks, and -execdir runs chown inside the directory find already holds open,
// so swapping a directory for a symlink mid-walk cannot redirect it; chown -h changes a link itself.
// Files with more than one hard link may share an inode with a file outside the workspace and are skipped.
async function chownTree(dir, config) {
	await execFileAsync("find", [
		"-P", dir,
		"(", "!", "-uid", String(config.uid), "-o", "!", "-gid", String(config.gid), ")",
		"(", "-type", "d", "-o", "-links", "1", ")",
		"-execdir", "chown", "-h", `${config.uid}:${config.gid}`, "{}", "+"
	], { env: { PATH: "/usr/bin:/bin" } });
}

async function existingDirs(paths) {
	const existing = [];
	for (const p of paths) {
		const stat = await fs.lstat(p).catch(() => undefined);
		if (stat?.isDirectory()) existing.push(p);
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

// Every provision checks paths and secrets before anything is handed to the sandbox uid.
async function prepareHost(config, workspaceDir) {
	if (typeof process.getuid !== "function" || process.getuid() !== 0) {
		throw new Error("local-user sandbox needs the Gateway to run as root so it can switch tools to the sandbox uid.");
	}
	const protectedReal = await protectedPaths(resolveStateDir());
	const workspace = await assertSafeSandboxDir("workspace", workspaceDir, protectedReal);
	const home = await assertSafeSandboxDir("home", config.home, protectedReal);
	await fs.mkdir(home, { recursive: true, mode: 0o700 });
	if (!(await fs.lstat(home)).isDirectory()) throw new Error(`local-user sandbox home ${home} must be a directory.`);
	await fs.lchown(home, config.uid, config.gid);
	await fs.chmod(home, 0o700);
	const existingProtected = await existingDirs(protectedReal);
	await tightenProtectedPaths(existingProtected);
	await selfTest(config, "", existingProtected);
	// Files the Gateway writes as root (for example reset hooks) are handed over on each provision.
	await chownTree(workspace, config);
	await selfTest(config, workspace, []);
}

export function createLocalUserSandboxBackendFactory(config) {
	return async (params) => {
		if ((params.cfg.docker?.binds?.length ?? 0) > 0) {
			throw new Error("local-user sandbox backend does not support sandbox.docker.binds.");
		}
		const workspaceDir = path.resolve(params.workspaceDir);
		params.assertRuntimeCurrent?.();
		await prepareHost(config, workspaceDir);
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
