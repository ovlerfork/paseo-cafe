import type { PluginHandlerContext } from "@getpaseo/plugin/server"
import { describe, expect, it, vi } from "vitest"
import { reviewPluginCandidate } from "./security-review"

const candidate = {
  provider: "codex/test-model",
  repositoryPath: "/tmp/plugin-candidate",
  refName: "candidate",
}

function reviewer(lastMessage: string, archiveError: string | null = null) {
  const archive = vi.fn(async () => ({
    archivedAt: archiveError ? null : "2026-11-18T00:00:00.000Z",
    error: archiveError,
  }))
  const paseo = {
    workspaces: {
      create: async () => ({
        archive,
        agents: {
          create: async () => ({
            waitForFinish: async () => ({ status: "idle", lastMessage }),
          }),
        },
      }),
    },
  } as unknown as PluginHandlerContext["paseo"]
  return { archive, paseo }
}

describe("plugin security review", () => {
  it("returns explicit approval after archiving the review workspace", async () => {
    const { archive, paseo } = reviewer(
      '{"approved":true,"reason":"No unsafe behavior found."}'
    )
    await expect(reviewPluginCandidate(paseo, candidate)).resolves.toEqual({
      approved: true,
      reason: "No unsafe behavior found.",
    })
    expect(archive).toHaveBeenCalled()
  })

  it("denies an invalid verdict and still archives the workspace", async () => {
    const { archive, paseo } = reviewer(
      '{"approved":"true","reason":"Looks safe."}'
    )
    await expect(
      reviewPluginCandidate(paseo, candidate)
    ).resolves.toMatchObject({
      approved: false,
    })
    expect(archive).toHaveBeenCalled()
  })

  it("denies an approval when the workspace cannot be archived", async () => {
    const { paseo } = reviewer(
      '{"approved":true,"reason":"No unsafe behavior found."}',
      "Archive failed"
    )
    await expect(
      reviewPluginCandidate(paseo, candidate)
    ).resolves.toMatchObject({
      approved: false,
    })
  })
})
