import policy = require('@lp-labs/policy-engine');
const engine = policy.createPolicyEngine({ policies: [] });
const allowed: boolean = engine.evaluate({ subject: 'u', action: 'read', resource: 'r' }).allowed;
void allowed;
