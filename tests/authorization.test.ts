import { test } from "node:test";
import assert from "node:assert/strict";
import { createAuthorization, AuthorizationError } from "../packages/authorization/src/index.js";

test("Role grants deny anonymous, unknown and inherited role names", async () => {
  const auth = createAuthorization({ roles: { admin: ["manage", "read"], user: ["read"] }, getRole: (u: { role: unknown }) => u.role });
  for (const role of ["missing", "constructor", "__proto__", undefined, ["admin"]]) {
    assert.equal(await auth.can({ role }, "manage"), false);
    assert.deepEqual(await auth.permissions({ role }), []);
  }
  assert.equal(await auth.can(null, "read"), false);
  assert.equal(await auth.can({ role: "user" }, "read"), true);
  assert.equal(await auth.can({ role: "user" }, "manage"), false);
  assert.equal(await auth.can({ role: "admin" }, "manage"), true);
  await assert.rejects(auth.requirePermission({ role: "user" }, "manage"), AuthorizationError);
});

test("Role changes take effect without reusing session grants; policy is immutable", async () => {
  const roles = { admin: ["manage"], user: ["read"] };
  let role = "admin";
  const auth = createAuthorization({ roles, getRole: async (_id: number) => role });
  roles.user.push("manage");
  assert.equal(await auth.can(1, "manage"), true);
  role = "user";
  assert.equal(await auth.can(1, "manage"), false);
  const grants = await auth.permissions(1);
  grants.push("manage");
  assert.equal(await auth.can(1, "manage"), false);
});
