# IDOR / BOLA — the method

> **This is a test of your ability to find broken object-level authorization** in the target the
> human names. Model who the principal is, what object they're reaching, **which reference names
> it**, and **which check was supposed to stand between them** — then find the request where the
> check ran against the wrong noun. The hard parts are not swapping an id: they are **establishing
> an oracle** and **showing how the id is obtained**. Work this with
> `playbooks/vulns/_master-vuln-hunting.md`.

**Read this file every time.** Technique catalogues live in **`ref/idor-bola.md`** — open a section
only when its trigger fires:

| you observe | open `ref/idor-bola.md` § |
|---|---|
| The request names two objects, or carries your identity | **I1** the check ran against the wrong noun |
| You're looking for where references hide | **I2** identifier locations & opaque blobs |
| The id looks unguessable | **I3** obtaining the id |
| The response tells you nothing | **I4** oracles that aren't the response body |
| The UI enforces something | **I5** alternate routes, other clients, other hosts |
| You had access and then lost it | **I6** grant-time vs use-time |
| You're inside the victim's org, or hold a lesser role | **I7** roles and tenancy within an object |
| It isn't plain REST — GraphQL, gRPC, a WebSocket | **I8** transport specifics: how the object is named, and what the oracle is |
| Proving severity, or judging duplication | **I9** impact · **I11** novelty |
| Designing a PoC someone can safely reproduce | **I12** validation ethics |

---

## 1. Model the authorization before you touch anything

**PRINCIPAL** — who is acting, and *in which role*? Not just "attacker vs victim": a member of the
same org, a lower-privileged role acting on a higher one, a share recipient, someone who *used to*
have access, an unauthenticated caller. Ownership is rarely binary.

**OBJECT** — what is being reached, and **what does it authorize or control**? An object you cannot
read may still be one you can spend, revoke, delete, or attach to yourself.

**REFERENCE** — how is the object named in the request? A numeric id, a UUID, a natural key (email,
username, slug, card number), a composite URN, an encoded blob, a *name the user chose* — or the
hostname, the cookie, or the action-selector parameter sitting beside it.

**THE CHECK** — what authorization was *supposed* to happen, and against which noun? Most of the
corpus is simply **no check at all**, and you find those by swapping an id. The high-yield minority
— and the one testers systematically miss — is **a real check that ran correctly against the wrong
object**: the parent instead of the child, the URL instead of the body, the role instead of the
tenant, existence instead of access. Test for both; the second needs a different move (§4).

**ROOT CAUSE** — one of: no check at all · the check validated the parent and never joined the child
to it · identity was read from the request instead of the session · an existence lookup substituted
for an access lookup · the check ran at grant time and never again · it was enforced in the client,
the gateway, or one route, but not in the service or the sibling route · a role was checked but not a
tenant · the reference was treated as a secret rather than as input. **That answer is your
`fix_locus`** — and two endpoints missing the same check are two findings.

## 2. Derive candidates — reason about verbs and objects, not parameter names

1. **Enumerate the verbs, not the URLs.** Many APIs multiplex on an action selector — one route,
   many operations, one ACL (or none) covering all of them. The verb list usually lives in the JS
   bundle, not the URL space (**I2**).
2. **Hunt two-object verbs first.** Transfer · move · assign · share · invite · tag · add-to ·
   merge · link · review. You supply your own valid object for the checked slot and the victim's for
   the unchecked one. This shape is disproportionately productive (**I1**).
3. **Start from an observed restriction, then look for the second door.** A private channel, an
   unpublished draft, a disabled comment section, "you left the group", a viewer role — each names a
   rule that *exists*, so go find the route that skipped it (**I5**).
4. **Test the write direction as hard as the read direction**, and *attach-to-me* as hard as
   *read-from-them*. Creating, linking and deleting produced a large share of the corpus's findings.
5. **Read the code when it's open source, and diff sibling handlers** — one reporter found a bug by
   noticing that `campaign-delete.php` validated ownership inside its loop while `banner-delete.php`
   did not. Sibling routes diverging is a recurring theme; the loop-level diff is one clean instance.
6. **Follow the object across systems** — mobile clients, acquired apps on their own domains,
   regional hosts, export renderers, WebDAV, third-party beacons. Tenancy usually breaks at seams.
7. **Ask how this transport names objects and operations, then keep going.** The bug is
   transport-independent; only the addressing and the oracle change (**I8**). A REST path segment, a
   GraphQL global id or mutation argument, a protobuf message field, a WebSocket frame — all are the
   same `object-ref`. If you need to *recover the contract* first (introspection off, no descriptor,
   no schema), that is a separate job: `playbooks/workflows/investigate-graphql.md` ·
   `investigate-grpc.md` · `investigate-api-surface.md`. Come back here to test.

## 3. Establish the oracle *before* you swap anything

**This is where most false negatives come from.** The HTTP response is a hint, not the test — write
and delete IDORs routinely return a 302, a bare 200, an empty body, or an outright error while the
side effect fires. Decide in advance how you will observe the effect:

- **The victim's own session** — log in as B (second browser profile) and re-read the object.
- **A notification** — an email or in-app message delivered to B is proof, and sometimes the only proof.
- **A counter or balance** — a billing count, a quota, a list length that changes.
- **A second endpoint** — write via one route, read back via another.
- **The response's metadata** — headers, a redirect body, a CSV header row, an error string.
- **Result-set shape** — a filtered count or a date range can betray a private object never returned.

If you cannot name an oracle before testing, you are not ready to test.

## 4. Test → Confirm → Validate

**Accounts gate:** this class needs **≥2 principals**. Some findings need three, or a consenting
second human. Without them the honest result is `coverage = blocked (needs-account)` — not "not
vulnerable".

**TEST — does the reference reach the object?** Swap one id first; that finds the plain no-check
cases. Then, where the request names several objects, **keep everything you legitimately own and
change only the leaf** — that is what reaches a check applied to the wrong noun, and a whole-set swap
would instead hit the check that *does* work. **Outcome: a hypothesis.**

**CONFIRM — did a principal reach an object it shouldn't?**
1. Observe the effect through the oracle from §3, not through the response.
2. **Show how the id is obtained.** An IDOR without a demonstrated acquisition path is a severity
   downgrade — programs discount "requires knowledge of a valid id". Budget as much effort here as on
   the swap (**I3**). Before assuming you must guess it, check whether it is *published* by the app,
   chained from a response you're entitled to, or simply not validated at all.
3. **Rule out the false positives:** you may be seeing your own data with the victim's fields mixed
   in; the write may have silently created a *new* object on your side; the reference may need
   changing in two places at once; the "identity" field may not be the one the app actually keys on.
4. **Map the family.** Once one member falls, check sibling routes, other verbs on the dispatcher,
   and other operations accepting the same id type. Report by `fix_locus`.

**VALIDATE — the least that proves impact.** One object, one action, on data you created where
possible. Do not enumerate the range to size the impact — probe the *boundary* if you must, and say
what you did not do.

## 5. Safety, artifact, and PoC handoff

- **Never mass-enumerate real users' objects.** One or two ids proves the bug; a dump is an incident.
  If you must show scale, argue it from the id structure rather than by harvesting.
- **Prefer objects you own, or that a consenting participant owns.** Seeding your own records into a
  wordlist, creating a deliberately-private object for the triager, or asking the program for a test
  reference are all normal practice (**I12**).
- **Destructive verbs need care.** Delete, revoke, expire, deactivate and transfer are frequently
  irreversible for the victim. Prove them against your own second account, never a stranger's.
- If you touch a real user's data by accident, **say so in the report** and tell the program what to
  remediate.
- **Store the artifact**: the request pair, plus the *oracle* evidence — the victim-session view, the
  notification, the counter delta. **No artifact → HYPOTHESIS.**
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): the request to **Burp Repeater**, or a
  copy-pasteable `curl` for both principals, plus how the id was obtained. Reproducible in one action.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` — and for this
class the **principal column carries the weight**: "tested as org member", "tested as share
recipient", "tested as ex-member" are different cells with different answers. Record the `fix_locus`
from §1. Log negatives *with their oracle*, so the next session knows how you looked. Novelty: **I11**.
