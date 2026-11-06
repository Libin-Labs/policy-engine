# @lp-labs/policy-engine

Bounded, declarative policy matching with fail-closed decisions and explicit deny precedence. Zero
runtime and peer dependencies.

## Install

```sh
npm install @lp-labs/policy-engine
```

Includes ESM, CommonJS, and TypeScript declarations for Node 18+.

## Quickstart

```js
import { createPolicyEngine } from '@lp-labs/policy-engine';

const engine = createPolicyEngine({
  policies: [
    { id: 'read-reports', effect: 'allow', subject: '*', action: 'read', resource: '*' },
    {
      id: 'sensitive-deny',
      effect: 'deny',
      subject: '*',
      action: 'read',
      resource: 'report:private',
    },
  ],
});
const decision = engine.evaluate({
  subject: 'user:42',
  action: 'read',
  resource: 'report:private',
});
if (decision.allowed) throw new Error('Explicit deny must win');
```

CommonJS: `const { createPolicyEngine } = require('@lp-labs/policy-engine');`.

## API and types

Runtime export: `createPolicyEngine(options): PolicyEngine`.

Exported types:

- `PolicyEffect`: `'allow' | 'deny'`.
- `Policy`: unique `id`, `effect`, and string selectors `subject`, `action`, `resource`.
- `PolicyRequest`: concrete subject/action/resource strings to evaluate.
- `PolicyEngineOptions`: `policies` plus optional `maxPolicies` (default 10,000, maximum 100,000).
- `PolicyDecision`: boolean `allowed`, a `reason` (`allowed`, `explicit-deny`, or `no-match`), and
  IDs for all matching policies in configured order.
- `PolicyEngine`: `evaluate(request)` and `policies()` methods.

Selectors match exactly, or use `*` to match any one complete selector value. Values are
case-sensitive. No wildcard syntax inside a string is interpreted: `report:*` matches only that
literal string, not a prefix. A request is allowed only if at least one allow policy matches and no
deny policy matches. No match is denied. A deny overrides every allow, independent of order.

## Customization, trust boundary and limits

Use your application's trusted configuration to create an engine and map authenticated,
server-validated identities and resources into the request fields. This package is a pure matching
utility, not an authorization boundary: it does not authenticate subjects, validate resource
ownership, enforce decisions, protect a client/server boundary, or provide policy administration.
Do not treat client-supplied identity or context as trusted, and enforce authorization in the trusted
server for every operation. This package makes no security certification claim.

- Policy definitions are copied at construction. `policies()` returns detached copies.
- IDs and selectors must be nonempty trimmed strings no longer than 128 characters; IDs are unique.
- Malformed definitions or requests throw `TypeError`; invalid capacities and capacity overflow
  throw `RangeError`. Invalid configuration should prevent startup rather than broaden access.
- Evaluation scans up to the configured policy limit, O(P) per request; there are no callbacks,
  dynamic expressions, context predicates, persistence or network calls.

All exported API names: `createPolicyEngine`, `PolicyEffect`, `Policy`, `PolicyRequest`,
`PolicyEngineOptions`, `PolicyDecision`, `PolicyEngine`.

## Support

If this library is useful to you, consider supporting its maintenance with a [donation via PayPal](https://www.paypal.me/LibinPrasanth).

## Author

Created by [Libin Prasanth](https://www.linkedin.com/in/libinprasanth/). Connect on LinkedIn for updates and discussion.
