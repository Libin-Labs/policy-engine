import assert from 'node:assert/strict';
import test from 'node:test';
import { createPolicyEngine } from '../dist/esm/index.js';

const request = { subject: 'user:1', action: 'read', resource: 'invoice:9' };

test('allows only a matching explicit allow and defaults to deny', () => {
  const engine = createPolicyEngine({
    policies: [
      { id: 'read-own', effect: 'allow', subject: 'user:1', action: 'read', resource: 'invoice:9' },
    ],
  });
  assert.deepEqual(engine.evaluate(request), {
    allowed: true,
    reason: 'allowed',
    matchedPolicyIds: ['read-own'],
  });
  assert.deepEqual(createPolicyEngine({ policies: [] }).evaluate(request), {
    allowed: false,
    reason: 'no-match',
    matchedPolicyIds: [],
  });
});

test('explicit deny wins regardless of policy order or broader allow', () => {
  for (const policies of [
    [
      { id: 'broad', effect: 'allow', subject: '*', action: '*', resource: '*' },
      { id: 'blocked', effect: 'deny', subject: 'user:1', action: 'read', resource: 'invoice:9' },
    ],
    [
      { id: 'blocked', effect: 'deny', subject: 'user:1', action: 'read', resource: 'invoice:9' },
      { id: 'broad', effect: 'allow', subject: '*', action: '*', resource: '*' },
    ],
  ]) {
    assert.deepEqual(createPolicyEngine({ policies }).evaluate(request), {
      allowed: false,
      reason: 'explicit-deny',
      matchedPolicyIds: policies.map((policy) => policy.id),
    });
  }
});

test('supports exact selectors and independent wildcard dimensions', () => {
  const engine = createPolicyEngine({
    policies: [
      { id: 'user-read', effect: 'allow', subject: 'user:1', action: 'read', resource: '*' },
    ],
  });
  assert.equal(engine.evaluate(request).allowed, true);
  assert.equal(engine.evaluate({ ...request, action: 'write' }).reason, 'no-match');
});

test('copies and freezes policy snapshots and decisions', () => {
  const input = [{ id: 'allow', effect: 'allow', subject: '*', action: 'read', resource: '*' }];
  const engine = createPolicyEngine({ policies: input });
  input[0].effect = 'deny';
  const returned = engine.policies();
  returned[0].effect = 'deny';
  const decision = engine.evaluate(request);
  assert.equal(decision.allowed, true);
  assert.equal(Object.isFrozen(decision), true);
  assert.equal(Object.isFrozen(decision.matchedPolicyIds), true);
});

test('rejects malformed selectors, duplicate identifiers and capacity overflow', () => {
  assert.throws(
    () =>
      createPolicyEngine({
        policies: [{ id: 'x', effect: 'maybe', subject: '*', action: '*', resource: '*' }],
      }),
    TypeError,
  );
  assert.throws(
    () =>
      createPolicyEngine({
        policies: [
          { id: 'x', effect: 'allow', subject: '*', action: '*', resource: '*' },
          { id: 'x', effect: 'deny', subject: '*', action: '*', resource: '*' },
        ],
      }),
    /Duplicate/,
  );
  assert.throws(() => createPolicyEngine({ policies: [], maxPolicies: -1 }), RangeError);
  assert.throws(() => createPolicyEngine({ policies: Array(1) }), TypeError);
  assert.throws(() => createPolicyEngine({ policies: [, ,] }), TypeError);
  assert.throws(
    () =>
      createPolicyEngine({
        policies: [{ id: 'x', effect: 'allow', subject: '*', action: '*', resource: '*' }],
        maxPolicies: 0,
      }),
    RangeError,
  );
  assert.throws(
    () => createPolicyEngine({ policies: [] }).evaluate({ ...request, subject: '*' }),
    TypeError,
  );
});
