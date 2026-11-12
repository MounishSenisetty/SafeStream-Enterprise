// Who is calling. From a bearer token (index.ts), or from a person's verified
// Access identity in the console (console.ts), which hands it to the same
// handlers through `delegated`.

export interface Principal {
  tenant: string;
  kind: "admin" | "agent";
  /** The token's id (first 12 hex digits of its hash), or "console". */
  id: string;
  /** The token's label, or the console user's email. */
  label: string;
  /** Console sessions only. */
  role?: "viewer" | "admin";
}

/** Principals established by the console for a request it dispatches. */
export const delegated = new WeakMap<Request, Principal>();
