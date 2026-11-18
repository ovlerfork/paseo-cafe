import { isUtf8 } from "node:buffer"
import { execFile } from "node:child_process"
import { createHash } from "node:crypto"
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises"
import { devNull, tmpdir } from "node:os"
import { join } from "node:path"
import { Readable } from "node:stream"
import { pipeline } from "node:stream/promises"
import { promisify } from "node:util"
import { gunzipSync } from "node:zlib"
import { extract } from "tar-stream"
import type { DirectoryEntry } from "../shared/directory"

const runFile = promisify(execFile)
const maxBytes = 64 * 1024 * 1024
const maxFileBytes = 16 * 1024 * 1024
const maxFiles = 10_000
const commitPattern = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i

function httpsUrl(value: string): string {
  const url = new URL(value)
  if (url.protocol !== "https:" || url.username || url.password || url.hash) {
    throw new Error("Candidate URL must be HTTPS without credentials")
  }
  return url.href
}

function candidatePath(path: string): string {
  if (
    path.length > 4096 ||
    path.includes("\\") ||
    path.includes("\0") ||
    /^[a-z]:/i.test(path) ||
    path.split("/").some((part) => !part || part === "." || part === "..")
  ) {
    throw new Error("Invalid candidate path")
  }
  return path
}

async function git(cwd: string, ...args: string[]): Promise<Buffer> {
  const result = await runFile(
    "git",
    [
      "-c",
      `core.hooksPath=${join(cwd, ".disabled-hooks")}`,
      "-c",
      "protocol.allow=never",
      "-c",
      "protocol.https.allow=always",
      "-c",
      "http.followRedirects=false",
      "-c",
      "fetch.fsckObjects=true",
      "-c",
      "fetch.unpackLimit=1",
      ...args,
    ],
    {
      cwd,
      encoding: "buffer",
      maxBuffer: maxFileBytes,
      timeout: 60_000,
      env: {
        PATH: process.env.PATH,
        SYSTEMROOT: process.env.SYSTEMROOT,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: devNull,
        GIT_TERMINAL_PROMPT: "0",
      },
    }
  )
  return result.stdout
}

async function snapshot(directory: string) {
  await mkdir(directory)
  const index: { path: string; file: string; kind: string }[] = []
  const seen = new Set<string>()
  let bytes = 0
  return {
    async add(path: string, kind: string, data: Buffer) {
      candidatePath(path)
      bytes += data.length
      if (seen.has(path) || index.length >= maxFiles || bytes > maxBytes) {
        throw new Error("Candidate snapshot exceeds limits or repeats a path")
      }
      seen.add(path)
      // Candidate names, modes and link targets are data; only generated paths reach disk.
      const file = `${String(index.length + 1).padStart(5, "0")}.data`
      await writeFile(join(directory, file), data, { mode: 0o600 })
      index.push({ path, file, kind })
    },
    async finish() {
      if (index.length === 0) throw new Error("Candidate snapshot is empty")
      await writeFile(
        join(directory, "index.json"),
        JSON.stringify(index, null, 2)
      )
    },
  }
}

async function stageSource(
  root: string,
  target: string,
  remote: string,
  commit?: string,
  pluginPath?: string
): Promise<string> {
  if (commit !== undefined && !commitPattern.test(commit)) {
    throw new Error("Invalid candidate commit")
  }
  const scope =
    pluginPath && pluginPath !== "."
      ? candidatePath(pluginPath.replace(/\/$/, ""))
      : ""
  const source = join(root, "fetch")
  await mkdir(source)
  await git(
    source,
    "init",
    "--bare",
    "--template=",
    ...(commit?.length === 64 ? ["--object-format=sha256"] : [])
  )
  await git(
    source,
    "fetch",
    "--depth=1",
    "--no-tags",
    "--no-recurse-submodules",
    "--",
    httpsUrl(remote),
    commit ?? "HEAD"
  )
  const fetched = (
    await git(source, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
  )
    .toString()
    .trim()
  if (commit && fetched !== commit.toLowerCase()) {
    throw new Error("Git returned a different commit")
  }
  const tree = await git(source, "ls-tree", "-rz", fetched)
  if (!isUtf8(tree)) throw new Error("Candidate contains a non-UTF-8 path")
  const output = await snapshot(target)
  let inScope = !scope
  for (const line of tree.toString().split("\0").slice(0, -1)) {
    const entry = /^(100644|100755|120000) blob ([a-f0-9]+)\t([\s\S]+)$/.exec(
      line
    )
    if (!entry) throw new Error("Unsupported Git tree entry")
    const [, mode, object, path] = entry
    if (path.startsWith(`${scope}/`) && mode !== "120000") inScope = true
    const data = await git(source, "cat-file", "blob", object)
    await output.add(
      path,
      mode === "120000" ? "symlink" : mode === "100755" ? "executable" : "file",
      data
    )
  }
  if (!inScope)
    throw new Error("Plugin path is missing from the candidate commit")
  await output.finish()
  await rm(source, { recursive: true, force: true })
  return fetched
}

async function fetchPublished(resolved: string): Promise<Buffer> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 60_000)
  timer.unref()
  try {
    const response = await fetch(httpsUrl(resolved), {
      redirect: "error",
      signal: controller.signal,
    })
    if (!response.ok || !response.body)
      throw new Error("Candidate download failed")
    const chunks: Buffer[] = []
    let bytes = 0
    const reader = response.body.getReader()
    try {
      while (true) {
        const next = await reader.read()
        if (next.done) break
        bytes += next.value.length
        if (bytes > maxBytes)
          throw new Error("Candidate download exceeds size limit")
        chunks.push(Buffer.from(next.value))
      }
    } finally {
      await reader.cancel()
    }
    return Buffer.concat(chunks)
  } finally {
    clearTimeout(timer)
  }
}

async function stagePublished(
  target: string,
  resolved: string,
  integrity: string
) {
  const expected = /^sha512-([a-z0-9+/]{86}={0,2})$/i.exec(integrity)?.[1]
  if (!expected) throw new Error("Invalid candidate SHA-512 integrity")
  const compressed = await fetchPublished(resolved)
  const digest = createHash("sha512").update(compressed).digest("base64")
  if (digest.replace(/=+$/, "") !== expected.replace(/=+$/, "")) {
    throw new Error("Candidate did not match the registry integrity")
  }
  const tar = gunzipSync(compressed, { maxOutputLength: maxBytes })
  const output = await snapshot(target)
  const parser = extract()
  let entries = 0
  await Promise.all([
    pipeline(Readable.from([tar]), parser),
    (async () => {
      for await (const stream of parser) {
        const { name, type, size, mode } = stream.header
        if (
          ++entries > maxFiles ||
          !Number.isSafeInteger(size) ||
          (size ?? 0) < 0 ||
          (size ?? 0) > maxFileBytes
        ) {
          throw new Error("Published package exceeds archive limits")
        }
        if (type === "directory" && /^package\/?$/.test(name)) {
          stream.resume()
          continue
        }
        if (!name.startsWith("package/"))
          throw new Error("Invalid npm archive path")
        const relative = name.slice("package/".length)
        const path = candidatePath(
          type === "directory" ? relative.replace(/\/$/, "") : relative
        )
        if (type === "directory") {
          stream.resume()
          continue
        }
        if (type !== "file" && type !== "contiguous-file") {
          throw new Error("Unsupported npm archive entry")
        }
        const parts: Buffer[] = []
        for await (const chunk of stream) {
          if (!Buffer.isBuffer(chunk)) throw new Error("Invalid archive data")
          parts.push(chunk)
        }
        await output.add(
          path,
          mode & 0o111 ? "executable" : "file",
          Buffer.concat(parts)
        )
      }
    })(),
  ]).catch((error: unknown) => {
    parser.destroy()
    throw error
  })
  await output.finish()
}

export async function stagePluginCandidate({
  artifact,
  repository,
}: Pick<DirectoryEntry, "artifact" | "repository">) {
  const root = await mkdtemp(join(tmpdir(), "paseo-plugin-review-"))
  const cleanup = () => rm(root, { recursive: true, force: true })
  try {
    const repositoryPath = join(root, "review")
    await mkdir(repositoryPath)
    let sourceCommit: string | undefined
    if (artifact.kind === "git") {
      sourceCommit = await stageSource(
        root,
        join(repositoryPath, "source"),
        artifact.remote,
        artifact.commit,
        artifact.pluginPath
      )
    } else {
      await stagePublished(
        join(repositoryPath, "published"),
        artifact.resolved,
        artifact.integrity
      )
      if (repository.url) {
        sourceCommit = await stageSource(
          root,
          join(repositoryPath, "source"),
          repository.url,
          repository.commit
        )
      }
    }
    await writeFile(
      join(repositoryPath, "candidate.json"),
      JSON.stringify({ artifact, repository, sourceCommit }, null, 2)
    )
    await git(repositoryPath, "init", "--template=", "--initial-branch=main")
    await git(repositoryPath, "add", "--", ".")
    await git(
      repositoryPath,
      "-c",
      "user.name=Plugin Review",
      "-c",
      "user.email=review@localhost",
      "commit",
      "--no-gpg-sign",
      "-m",
      "Stage plugin review data"
    )
    return { repositoryPath, refName: "main" as const, cleanup }
  } catch (error) {
    await cleanup()
    throw error
  }
}
