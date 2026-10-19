export class AuthorizationError extends Error {
  readonly status = 403;
  constructor() {
    super("No tienes permiso para realizar esta acción");
    this.name = "AuthorizationError";
  }
}

export function createAuthorization<Subject, Permission extends string>(options: {
  roles: Readonly<Record<string, readonly Permission[]>>;
  getRole: (subject: Subject) => unknown | Promise<unknown>;
}) {
  // Copy the policy so callers cannot mutate grants after initialization.
  const roles = new Map(Object.entries(options.roles).map(([role, grants]) => [role, new Set(grants)]));
  async function permissions(subject: Subject | null | undefined): Promise<Permission[]> {
    if (subject == null) return [];
    const role = await options.getRole(subject);
    return typeof role === "string" ? [...(roles.get(role) ?? [])] : [];
  }
  async function can(subject: Subject | null | undefined, permission: Permission) {
    return (await permissions(subject)).includes(permission);
  }
  async function requirePermission(subject: Subject | null | undefined, permission: Permission) {
    if (!(await can(subject, permission))) throw new AuthorizationError();
  }
  return { permissions, can, requirePermission };
}
