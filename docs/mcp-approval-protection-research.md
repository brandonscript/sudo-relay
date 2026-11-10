# Can an MCP app disable agent control?

November 10, 2026. Research following the [live card failures](mcp-host-boundary-results.md). No plugin, production policy or host setting was changed for this research.

No documented per-widget “human only” or “disable agent control” security flag was found in the reviewed MCP Apps stable/draft specifications, OpenAI UI reference, OpenAI extension specification or installed `@modelcontextprotocol/ext-apps` 2.0.4 types. This is a bounded documentation finding, not a claim about every private or future host feature. There are narrower controls and alternative interaction paths worth testing.

## Controls we already use

The probe declares `_meta.ui.visibility: ["app"]` on its receipt tool and keeps its capability in result `_meta`. That removes the direct model-facing route in our observed host, but the agent operated the authorized widget instead. The [MCP Apps stable specification](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx) scopes visibility to model/app access; it also explicitly depicts a user or agent interacting with a view.

Iframe sandboxing and CSP restrict what the embedded app can do to its host and external origins. They do not promise that the host cannot inspect or operate that app. Our probe already uses empty external connection/resource domain lists. Adding more CSP restrictions cannot be presented as fixing the observed ordinary-button path.

The [OpenAI UI reference](https://developers.openai.com/plugins/reference) documents private metadata, app-only tool visibility, compatibility fields such as `openai/widgetAccessible`, and tool annotations. Turning widget tool access off would also remove its normal approval call. `destructiveHint` communicates a tool's effects to the host; it is not a per-widget automation prohibition or a broker-verifiable human-presence assertion. A host-owned modal created with `requestModal` still contains our template; the API does not document protected human consent.

## Candidate 1: keep the card inline

The [OpenAI extension specification](https://github.com/openai/mcp-extensions/blob/main/docs/spec.md#display-modes) supports this UI resource metadata:

```json
{
  "_meta": {
    "openai/ui": {
      "availableDisplayModes": ["inline"],
      "preferredDisplayMode": "inline"
    }
  }
}
```

The [MCP Apps draft](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/draft/apps.mdx#display-modes) also defines `appCapabilities.availableDisplayModes`; hosts must respect the declared modes. The installed SDK includes that capability. Our probe currently declares neither restriction.

**Hypothesis:** inline-only presentation may remove the specific route we demonstrated, since the supported MCP Apps browser provider exposed expanded side-panel cards, not inline cards. This is a display control, not a documented security boundary. The host may expose inline cards through another interface or change behavior later. It does not protect against a client or local process that can obtain the approval capability independently.

Test with a separate receipt-only variant: declare inline-only in both the UI initialization and resource metadata, verify expansion is unavailable, inspect the enabled automation interfaces, attempt approval where supported, then require a successful human control. Repeat on desktop and mobile before making a compatibility claim. Do not infer security merely from an empty tab inventory.

## Candidate 2: let the host ask for confirmation

MCP form elicitation asks the client to collect a structured response instead of giving our HTML widget an approval button. OpenAI documents [native extended forms](https://developers.openai.com/plugins/build/extensions#extended-forms); its extension specification lists desktop support, but not iOS/Android support for those extended forms. Direct connections and registered servers use different protocol flows, so capability negotiation matters.

This could preserve an in-chat interaction while moving the last confirmation outside the exposed iframe. It is a candidate, not established human authentication. The elicitation protocol leaves presentation to the client; a response saying `accept` alone does not prove that a person provided it.

Test a fixed-command receipt flow with no app-callable approval endpoint. Check real-host capability support, explicit human accept/decline, cancellation and expiry, and whether supported agent tools can submit the native form or forge its response. Bind the server's pending decision to the authenticated client/session, request ID, nonce and digest. Never collect passwords or credentials in a form. A genuine native permission restriction must be recorded, not bypassed to finish the test.

## Candidate 3: protected URL elicitation

The [MCP elicitation specification](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation#safe-url-handling) requires URL-mode interactions to open in a way that prevents client/LLM inspection of content and inputs. This is a stronger stated isolation requirement than ordinary widget rendering or `openExternal`.

It is not an all-inline UI flag, and this Codex build's support and enforcement remain untested. The URL cannot itself grant access; the approval service must authenticate the person and bind their decision to the pending request. Accepting the host's navigation prompt is not completion of the approval. The server must verify the out-of-band result. Test that distinction, session identity, replay and whether the resulting review view is accessible to any enabled automation route. Do not assume opening a normal browser tab satisfies the requirement.

## A small mitigation that is not a security boundary

An event `isTrusted` check can reject some script-dispatched input. The [DOM standard](https://dom.spec.whatwg.org/#dom-event-istrusted) defines it as browser-originated versus script-dispatched, not human versus agent. The [WebDriver specification](https://www.w3.org/TR/webdriver/#actions) requires automation to dispatch trusted events. Therefore it cannot prove human presence.

Our tested MCP Apps provider described its clicks as synthetic, so checking input/click/keyboard provenance is worth a disposable experiment. Checking only the form's submit event may miss browser-generated submission following another event. A client-side boolean sent to the server is not an attestation. Any such filter must preserve keyboard and assistive-technology use, and must not replace the approval boundary.

## Recommended order

1. Test inline-only metadata first: the smallest change, directly aimed at the observed path, while retaining the current experience.
2. Test host-rendered elicitation separately, to determine whether this host offers a protected final confirmation without biometrics.
3. Evaluate URL elicitation if leaving the card is acceptable. Keep the existing optional passkey/Touch ID work separate from claims about UI isolation.

If none gives a documented and demonstrated protected confirmation path, ask the host vendor for a supported per-widget automation exclusion or authenticated, request-bound human-confirmation API. A developer-invented metadata field is not a fix unless the host recognizes and enforces it. No vendor contact was made.

These candidates have not been implemented or live-tested. The confirmed failures remain valid; no broader “safe when Computer Use is off” claim follows from this research.
