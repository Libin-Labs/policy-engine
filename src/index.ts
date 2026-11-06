export type PolicyEffect = 'allow' | 'deny';

export interface Policy {
  id: string;
  effect: PolicyEffect;
  subject: string;
  action: string;
  resource: string;
}

export interface PolicyRequest {
  subject: string;
  action: string;
  resource: string;
}

export interface PolicyEngineOptions {
  policies: readonly Policy[];
  maxPolicies?: number;
}

export interface PolicyDecision {
  readonly allowed: boolean;
  readonly reason: 'allowed' | 'explicit-deny' | 'no-match';
  readonly matchedPolicyIds: readonly string[];
}

export interface PolicyEngine {
  evaluate(request: PolicyRequest): PolicyDecision;
  policies(): readonly Policy[];
}

function label(value: unknown, name: string, wildcard = false): string {
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > 128 ||
    value.trim() !== value ||
    (!wildcard && value === '*')
  ) {
    throw new TypeError(`${name} must be a nonempty string of at most 128 characters.`);
  }
  return value;
}

function fields(
  input: unknown,
  name: string,
  allowed: readonly string[],
  required: readonly string[],
): Record<string, unknown> {
  if (!input || typeof input !== 'object' || Array.isArray(input))
    throw new TypeError(`${name} must be an object.`);
  const prototype = Object.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null)
    throw new TypeError(`${name} must be a plain record.`);
  const result: Record<string, unknown> = {};
  for (const key of Reflect.ownKeys(input)) {
    if (typeof key !== 'string' || !allowed.includes(key))
      throw new TypeError(`${name} contains an unsupported property.`);
    const descriptor = Object.getOwnPropertyDescriptor(input, key)!;
    if (!descriptor.enumerable || !('value' in descriptor))
      throw new TypeError(`${name} properties must be enumerable data properties.`);
    result[key] = descriptor.value;
  }
  for (const key of required) {
    if (!Object.hasOwn(result, key)) throw new TypeError(`${name} is missing ${key}.`);
  }
  return result;
}

function copyPolicy(input: Policy): Policy {
  const value = fields(
    input,
    'Policy',
    ['id', 'effect', 'subject', 'action', 'resource'],
    ['id', 'effect', 'subject', 'action', 'resource'],
  );
  const id = label(value.id, 'Policy ID');
  if (value.effect !== 'allow' && value.effect !== 'deny')
    throw new TypeError('Policy effect must be allow or deny.');
  return Object.freeze({
    id,
    effect: value.effect,
    subject: label(value.subject, 'Policy subject', true),
    action: label(value.action, 'Policy action', true),
    resource: label(value.resource, 'Policy resource', true),
  });
}

function matches(selector: string, value: string): boolean {
  return selector === '*' || selector === value;
}

/** Creates an in-memory, fail-closed policy evaluator; this is not an authorization boundary. */
export function createPolicyEngine(options: PolicyEngineOptions): PolicyEngine {
  const config = fields(options, 'options', ['policies', 'maxPolicies'], ['policies']);
  if (!Array.isArray(config.policies)) throw new TypeError('options.policies must be an array.');
  const maximum = (config.maxPolicies as number | undefined) ?? 10_000;
  if (!Number.isSafeInteger(maximum) || maximum < 0 || maximum > 100_000)
    throw new RangeError('maxPolicies must be an integer from 0 to 100000.');
  const inputPolicies = config.policies as readonly Policy[];
  if (inputPolicies.length > maximum) throw new RangeError('Policy capacity exceeded.');
  if (
    Object.getPrototypeOf(inputPolicies) !== Array.prototype ||
    Reflect.ownKeys(inputPolicies).length !== inputPolicies.length + 1
  ) {
    throw new TypeError('options.policies must be a dense array without extra properties.');
  }
  const ids = new Set<string>();
  const policies: Policy[] = [];
  for (let index = 0; index < inputPolicies.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(inputPolicies, String(index));
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor))
      throw new TypeError('options.policies must contain data entries at every index.');
    const policy = copyPolicy(descriptor.value as Policy);
    if (ids.has(policy.id)) throw new TypeError(`Duplicate policy ID: ${policy.id}`);
    ids.add(policy.id);
    policies.push(policy);
  }
  const snapshot = Object.freeze(policies);
  return Object.freeze({
    policies: () => snapshot.map((policy) => ({ ...policy })),
    evaluate(request: PolicyRequest): PolicyDecision {
      const value = fields(
        request,
        'request',
        ['subject', 'action', 'resource'],
        ['subject', 'action', 'resource'],
      );
      const subject = label(value.subject, 'Request subject');
      const action = label(value.action, 'Request action');
      const resource = label(value.resource, 'Request resource');
      const matched = policies.filter(
        (policy) =>
          matches(policy.subject, subject) &&
          matches(policy.action, action) &&
          matches(policy.resource, resource),
      );
      const denied = matched.some((policy) => policy.effect === 'deny');
      const allowed = !denied && matched.some((policy) => policy.effect === 'allow');
      const reason = denied ? 'explicit-deny' : allowed ? 'allowed' : 'no-match';
      return Object.freeze({
        allowed,
        reason,
        matchedPolicyIds: Object.freeze(matched.map((policy) => policy.id)),
      });
    },
  });
}
