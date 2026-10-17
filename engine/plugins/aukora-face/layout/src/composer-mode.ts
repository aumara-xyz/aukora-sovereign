import type { Context } from '@deepseek-ai/cordis'
import { z } from 'zod'
import { CommandDefinitionId } from '@deepseek-ai/dsh-commands/brand'
import { setSandboxMode } from '@deepseek-ai/dsh-sandbox-policy'
import type {} from '@deepseek-ai/dsh-agent'
import type {} from '@deepseek-ai/dsh-commands'
import type {} from '@deepseek-ai/dsh-session-projection'
import type {} from './composer-mode-types.ts'

/**
 * Require the deployment boundary before a mode change is accepted. This is Prime's `requiredConfinement`
 * (added to `@deepseek-ai/dsh-sandbox` by Prime's `patches/mandatory-agent-confinement.patch.json`; upstream
 * DSH 0.2.1-alpha.5 does not export it), reduced to the two guards this file used: the `aukoraConfinement`
 * provider must exist, and the policy must be a confined mode with a workspace root.
 * @param ctx - scope that may carry the `aukoraConfinement` provider.
 * @param policy - the resolved sandbox policy for the requested mode.
 */
function requiredConfinement(ctx: Context, policy: unknown): void {
  const provider = ctx.get('aukoraConfinement') as { confine?: unknown } | undefined
  if (provider === undefined || typeof provider.confine !== 'function') {
    throw new Error('AUKORA_CONFINEMENT_REQUIRED: required native confinement is unavailable')
  }
  if (policy === null || typeof policy !== 'object' || Array.isArray(policy)) {
    throw new Error('AUKORA_CONFINEMENT_POLICY: a resolved confined policy is required')
  }
  const input = policy as { mode?: unknown; workspaceRoot?: unknown }
  if ((input.mode !== 'read-only' && input.mode !== 'workspace-write')
    || typeof input.workspaceRoot !== 'string' || input.workspaceRoot.length === 0) {
    throw new Error('AUKORA_CONFINEMENT_POLICY: read-only or workspace-write with a workspaceRoot is required')
  }
}

/** Registers a read-only projection and a sandbox-only command. Installation never changes session state. */
export function installComposerMode(ctx: Context): void {
  ctx.inject(['sessionProjections', 'commands', 'sandboxPolicy'], scope => {
    const modeSchema = z.enum(['read-only', 'workspace-write', 'danger-full-access'])
    scope.sessionProjections.register({
      key: 'aukoraComposerMode', stateVersion: 1, stateSchema: modeSchema.nullable(),
      init: () => null,
      apply: (state, event) => event.type === 'sandbox/mode' ? event.data.mode : state,
      wire: {
        viewSchema: z.object({ mode: modeSchema, available: z.boolean() }),
        view: state => ({
          mode: state ?? scope.sandboxPolicy.defaultMode,
          available: typeof scope.get('aukoraConfinement')?.confine === 'function',
        }),
      },
    })
    scope.commands.register({
      definitionId: CommandDefinitionId('@aukora/composer-mode'), name: 'aukora-mode',
      description: 'Select confined Chat or Build mode without changing approval policy', input: { hint: '<read-only|workspace-write>' },
      handler: ({ agent, rawInput }) => {
        const requested = rawInput.trim()
        if (requested !== 'read-only' && requested !== 'workspace-write') {
          return { kind: 'error', text: 'Only Chat or Build is offered.' }
        }
        try {
          const policy = scope.sandboxPolicy.resolve({ session: agent.session, mode: requested })
          requiredConfinement(scope, policy)
          if (scope.sandboxPolicy.resolve({ session: agent.session }).mode !== requested) {
            setSandboxMode(agent.session, requested)
          }
          if (scope.sandboxPolicy.resolve({ session: agent.session }).mode !== requested) {
            return { kind: 'error', text: 'The host did not confirm the requested sandbox mode.' }
          }
          return { kind: 'success', text: requested === 'read-only' ? 'Chat mode' : 'Build mode' }
        } catch {
          return { kind: 'error', text: 'Mode change unavailable; check the host-reported state.' }
        }
      },
    })
  })
}
