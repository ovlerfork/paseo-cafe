import { usePaseo, useRpc, useSettings } from "@getpaseo/plugin/client"
import { useToast } from "@getpaseo/plugin/client/react-native"
import type { SettingsInputHandle } from "@getpaseo/plugin/client/ui"
import {
  SettingsAction,
  SettingsCard,
  SettingsInput,
  SettingsRow,
  SettingsSection,
  SettingsSelect,
} from "@getpaseo/plugin/client/ui"
import { useQuery } from "@tanstack/react-query"
import { useRef, useState } from "react"
import {
  DEFAULT_REGISTRY_URL,
  directoryRunAutomaticUpdatesRpc,
  directorySettings,
  isTrustedRegistryUrl,
  registryBase,
} from "../shared/directory"
import { summarizeAutomaticUpdates } from "./update-status"

const REGISTRY_INFO =
  "Paseo Cafe browses the official Paseo plugin directory. To browse another registry, it must serve the Paseo registry protocol v1 documents (index.json and plugins/<owner>/<slug>.json) over HTTPS, or HTTP on localhost. The registry decides what the paseo CLI installs, so only use one you trust. Installing from a custom registry also needs an HTTPS URL without a path."

export function DirectorySettings() {
  const settings = useSettings(directorySettings)
  const paseo = usePaseo()
  const reviewModels = useQuery({
    queryKey: ["codex-review-models"],
    enabled: settings.status === "ready",
    queryFn: async () => {
      const { models, error } = await paseo.providers.listModels("codex")
      if (error) throw new Error(error)
      return (models ?? []).flatMap(({ id, label, isSelectable }) => {
        const value = `codex/${id}`
        return isSelectable !== false &&
          /^codex\/\S+$/.test(value) &&
          value.length <= 200
          ? [{ value, label }]
          : []
      })
    },
  })
  const runAutomaticUpdates = useRpc(directoryRunAutomaticUpdatesRpc)
  const toast = useToast()
  const [draft, setDraft] = useState<string | null>(null)
  const inputRef = useRef<SettingsInputHandle>(null)
  const [checkingUpdates, setCheckingUpdates] = useState(false)

  if (settings.status === "loading") return null

  if (settings.status === "error" || settings.status === "invalid") {
    return (
      <SettingsSection title="Paseo Cafe">
        <SettingsRow label="Registry URL" error={settings.error} />
        <SettingsAction
          label="Try again"
          actionLabel="Reload"
          onPress={settings.reload}
        />
        {settings.status === "invalid" ? (
          <SettingsAction
            label="Restore default settings"
            actionLabel="Reset"
            onPress={settings.reset}
          />
        ) : null}
      </SettingsSection>
    )
  }

  // Destructured once, right after narrowing: TypeScript doesn't carry
  // `settings.status === "ready"` narrowing into a closure defined below, but
  // these individual bindings keep their (already-narrowed) types fine.
  const { values, revision, saving, saveError, save: saveSettings } = settings
  const modelOptions = reviewModels.data ?? []
  const reviewOptions = [{ value: "", label: "None" }, ...modelOptions]
  if (
    values.reviewProvider &&
    !reviewOptions.some(({ value }) => value === values.reviewProvider)
  ) {
    reviewOptions.push({
      value: values.reviewProvider,
      label: values.reviewProvider,
    })
  }
  const currentUrl = draft ?? values.registryUrl
  const urlValid = isTrustedRegistryUrl(currentUrl)
  const dirty = registryBase(currentUrl) !== registryBase(values.registryUrl)
  const usingOfficialRegistry =
    registryBase(currentUrl) === DEFAULT_REGISTRY_URL &&
    registryBase(values.registryUrl) === DEFAULT_REGISTRY_URL

  async function apply(url: string) {
    const registryUrl = registryBase(url)
    const ok = await saveSettings({ ...values, registryUrl }, revision)
    if (ok) {
      setDraft(null)
      inputRef.current?.replaceText(registryUrl)
      toast.show("Paseo Cafe settings saved.", { variant: "success" })
    } else {
      toast.error("Failed to save Paseo Cafe settings.")
    }
  }

  async function saveReviewModel(reviewProvider: string) {
    if (reviewProvider === values.reviewProvider) return
    const ok = await saveSettings({ ...values, reviewProvider }, revision)
    if (ok) toast.show("Security review model saved.", { variant: "success" })
    else toast.error("Failed to save the security review model.")
  }

  function reset() {
    inputRef.current?.replaceText(DEFAULT_REGISTRY_URL)
    setDraft(DEFAULT_REGISTRY_URL)
    void apply(DEFAULT_REGISTRY_URL)
  }

  async function runUpdatesNow() {
    setCheckingUpdates(true)
    try {
      const { outcomes } = await runAutomaticUpdates({})
      const summary = summarizeAutomaticUpdates(outcomes)
      if (summary.failed) toast.error(summary.message)
      else toast.show(summary.message, { variant: "success" })
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Automatic update run failed."
      )
    } finally {
      setCheckingUpdates(false)
    }
  }

  return (
    <SettingsSection title="Paseo Cafe" info={REGISTRY_INFO}>
      <SettingsCard>
        <SettingsInput
          ref={inputRef}
          label="Registry URL"
          hint={`HTTPS, or HTTP on localhost. Official registry: ${DEFAULT_REGISTRY_URL}`}
          error={
            draft !== null && !urlValid
              ? "Use an HTTPS URL, or HTTP on localhost."
              : saveError
          }
          initialValue={values.registryUrl}
          placeholder={DEFAULT_REGISTRY_URL}
          onChangeText={setDraft}
          disabled={saving}
        />
        <SettingsAction
          label="Apply"
          actionLabel={saving ? "Saving…" : "Save"}
          disabled={saving || !dirty || !urlValid}
          onPress={() => void apply(currentUrl)}
        />
        <SettingsAction
          label="Default"
          actionLabel="Reset to official registry"
          disabled={saving || usingOfficialRegistry}
          onPress={reset}
        />
        <SettingsSelect
          label="Security review model"
          hint="Codex receives candidate plugin contents for review. Without a model, no review runs and installs and updates are blocked."
          error={saveError}
          value={values.reviewProvider}
          options={reviewOptions}
          disabled={
            saving || (modelOptions.length === 0 && !values.reviewProvider)
          }
          onValueChange={(model) => void saveReviewModel(model)}
        />
        {reviewModels.isFetching && modelOptions.length === 0 ? (
          <SettingsRow label="Loading Codex models…" />
        ) : reviewModels.isError || modelOptions.length === 0 ? (
          <SettingsAction
            label={
              reviewModels.isError
                ? "Could not load Codex models"
                : "No Codex models available on this host"
            }
            error={reviewModels.error?.message}
            actionLabel="Retry"
            onPress={() => void reviewModels.refetch()}
          />
        ) : null}
        <SettingsAction
          label="Run automatic updates now"
          hint="Installed plugins update on their own every 6 hours unless automatic updates are off for them. Run the check now instead of waiting."
          actionLabel={checkingUpdates ? "Running…" : "Run now"}
          disabled={checkingUpdates}
          onPress={() => void runUpdatesNow()}
        />
      </SettingsCard>
    </SettingsSection>
  )
}
