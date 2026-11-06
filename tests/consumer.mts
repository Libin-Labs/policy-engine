import { createPolicyEngine, type Policy, type PolicyDecision } from '@lp-labs/policy-engine';
const policies: Policy[] = [
  { id: 'public-read', effect: 'allow', subject: '*', action: 'read', resource: '*' },
];
const engine = createPolicyEngine({ policies });
const result: PolicyDecision = engine.evaluate({
  subject: 'user:42',
  action: 'read',
  resource: 'report:7',
});
void result.allowed;
