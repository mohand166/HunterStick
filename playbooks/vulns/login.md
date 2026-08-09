# Login / Authentication Logic → split

**This playbook has been split.** It conflated two classes that share a flow but differ in oracle,
account requirement and severity:

| you want | go to |
|---|---|
| Reach an authenticated session without the right secret — trusted client field, a param that flips the decision, an alternate path skipping MFA/lockout, default creds | **[`authentication-bypass.md`](authentication-bypass.md)** |
| Find a valid-account oracle — behaviour that differs by whether an identity exists, on any channel | **[`user-enumeration.md`](user-enumeration.md)** |

Why the split: the **oracles are different** (an authenticated action you couldn't perform before,
versus a stable account-dependent difference), the **account gates are different** (one account you
own to land in, versus two identities — one valid, one known-invalid), and the **severity is
different** (account or admin takeover, versus low/informational whose value is as an enabler).
Keeping them in one file meant one §4 with two of everything.

Both files keep the shared discipline: never brute-force, credential-stuff, or lock out a real user;
enumerate auth *paths* rather than passwords; and log the entrypoint per path, because web form,
mobile API and GraphQL are different code with different answers.
