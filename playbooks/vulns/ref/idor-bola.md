# IDOR / BOLA — reference layer

> **Lookup, not reading.** Open a section when its trigger fires; don't read this end to end.
> The method lives in `../idor-bola.md` — that one you read every time.
>
> Grounded in 195 disclosed HackerOne reports (`knowledge/reports/idor-bola/`). `[#id]` =
> hackerone.com/reports/id. **Corpus bias:** heavy on consumer platforms, telco/gov estates and
> open-source products; **35% of the files are team-summary stubs with no artifact**.
>
> ⚠️ **Access assumption:** a large fraction of these findings required access an ordinary tester
> does not have — an invited org role, a program security-team seat, a merchant/advertiser account,
> a paid tier, a CAC smart card, or a self-hosted install. Some are flagged inline, **but the
> flagging is incomplete** — assume any cited report may carry an access precondition and check the
> report before presenting a technique as ordinarily reachable.
>
> ⚠️ **Disposition:** presence in this corpus is not acceptance. Of the citations here, 9 were closed
> `informative`, `duplicate` or `not-applicable` — each is marked inline. Verify with
> `knowledge/tools/check-dispositions.py idor-bola`. Reason from the model in `../idor-bola.md` §1.

| § | trigger |
|---|---|
| **I1** | the request names two objects, or carries your identity |
| **I2** | where references hide, and how to decode them |
| **I3** | obtaining the id |
| **I4** | oracles that aren't the response body |
| **I5** | alternate routes, other clients, other hosts |
| **I6** | grant-time vs use-time |
| **I7** | roles and tenancy within an object |
| **I8** | transport specifics — GraphQL · gRPC · WebSocket |
| **I9** | impact & escalation |
| **I10** | false negatives and false positives |
| **I11** | novelty and duplication |
| **I12** | validation ethics |
| **I13** | worked examples |

---

## I1. The check ran against the wrong noun

**Most of the corpus is a plainly missing check.** This section is about the harder minority: a real
check that ran correctly against the *wrong* object. Those are the ones a whole-set id swap misses,
so enumerate every identifier in the request and ask which one the check plausibly used.

### Two-object verbs
Transfer, move, assign, share, invite, tag, add-to, merge, review — the first noun is checked, the
second is not. Supply your own valid object for the checked slot and the victim's for the other:
a balance-transfer where the *second* card number was never scoped [#858662] · "Move to → My
Content" with a foreign content id [#915127] · assigning an inbox message to any `userid` [#1816900]
· a review form carrying `report_id` (yours) and `hacker_username` (arbitrary) [#262661] · adding a
co-founder to another merchant's application [#1066203, needs prior Admin access] · adding an
attendee to an event [#1734639] · adding products into another user's catalogue [#1527906,
#2848610 — both need an advertiser account].

### Parent checked, child unchecked — keep what you own, change one leaf
An open-source ad server validated `clientid` and `campaignid` (both the attacker's own, so they
pass) then looped over `bannerid` with no ownership check at all [#3401612, self-hosted lab]. A CSV
export succeeded with a foreign report id in a `report_ids[]` array alongside one of the reporter's
own [#510759, needs program team access]. Photo ids never joined to the restaurant you own [#404797,
needs manager accounts]. A status-check id never scoped to the project in the path — and the response
returned the private project's name, external URL, protected-branch rules and privileged usernames
[#1372216, needs a paid trial]. **The move is to keep every id you own and change only the leaf; a
whole-set swap would instead meet the check that works.**

### URL authorized, body executed
Authorization verified against the repo in the path; the change applied to the repo named by
`owner_id` in the body [#3560256, self-hosted product, needs repo admin].

### Client-asserted identity
**A request that carries your identity is telling you the server doesn't trust its own session.**
The presence of `userId` / `UserId` / `VendorId` / `personId` beside the object id is the finding
before you even test it: `userId` next to `transcriptId` [#547663] · next to `courseId` [#783708] ·
`UserId` and `Id` in one multipart body, where changing `Id` rewrote another candidate's demographics
[#2586662] · a `steamid=` **cookie** beside a valid session deciding whose data is read and written
[#990878] · `UID2` in a cookie plus `userName` in the body driving a password change [#1004750] · a
session-authenticated `POST /v1/account/destroy` whose JSON body named the *target* account rather
than the session's — though it also carried the victim's `authPW`, harvested from their session, and
the accepted impact was scoped to SSO-registered users [#3154983].

### Redundant identifiers — the server keys off the untrusted one
Whenever a request contains two ways to name the same actor or object, one of them is unvalidated:
`report_id` + `hacker_username` [#262661] · `userId` + `projectId` [#587687] · `id` + `email`
[#1698006] · a `profileId` appearing both in a URN tuple and a separate `sectionUrn` [#1608735].
Related: the "identity" field you swap may not be the one the app keys on — changing `email` did
nothing because the login identity was `username`, which happened to contain an email [#1272478].

### Existence check substituted for access check
A single-object fetch helper called with no room/tenant argument — `findOneById(messageId)` succeeds
and the membership predicate is simply never invoked, returning full message content from any private
group or DM [#3713682]. A `findOne` with no scope argument is the code smell.

### Create accepts an arbitrary parent or owner
Nothing validates that you may attach to the referenced parent, or that the object you're attaching
is free: a venue created under anyone's `parent` [#120312] · linking someone else's payment card to
your rewards account, which the program assessed as *may have* exposed its transaction history
[#358143] · assigning secondary users from
other accounts to your business account [#415081] · an application that **moves to your account**
when you change its id [#1695454, the program granted a test account] · confirming an email address
you don't own [#244636].

## I2. Where references hide, and how to decode them

Beyond path/query/body/cookie:

- **The action-selector parameter**, not the id — `strCall=DeleteProfilePicture` [#2213900],
  `tab=treat_subscription` [#313050], `action=comment_edit_form` [#52181], `p=subscribe` →
  `p=unsubscribe` [#230328], `request_type=deactivate-special-menu` recovered from the JS bundle
  [#264919]. One route, many operations, one ACL. **Enumerate the verb list from JS, not the URLs.**
- **A form-type selector that switches one endpoint between public and administrative behaviour** —
  `sendingForm=<n>` on an endpoint serving login, forgot-password *and* admin user lookup, reachable
  unauthenticated [#685338, #1048540].
- **The hostname** — regional API subdomains that skipped the API-key check the canonical host
  enforced, found with a `site:` search [#284963, informative]; sibling hosts sharing a session store [#876300].
- **multipart/form-data field names** [#2586662] · **hidden HTML inputs** found by grepping the
  rendered page [#974222, #766437] · **the `Referer` header as a duplicate id** that must be changed
  in lockstep or the request fails [#1085743].
- **Natural keys that need no enumeration** — an email address as the whole key [#1773609], as a
  WebDAV path segment [#3518758]; a public username [#2618486, informative]; a user-chosen object **name**
  [#1472721]; a printed card number [#766437]; an org id published in the program's own policy page
  [#2487889].
- **Composite and structured references** — a URL-encoded URN tuple holding two substitutable ids
  [#1592587]; a colon-delimited pseudo-path where the "token" is `vendor-epoch-counter` and only the
  last digits vary [#1182465]; a rails bracketed param [#1695454]; a generic update-DSL envelope with
  the id three levels down [#1773609].
- **Arrays** — `photo_ids[]` in a GET query string performing a destructive delete [#404797];
  `orderKeys[]` [#544329]; a filter array whose foreign values silently apply [#663431]; a batch
  array **mixing your own and foreign ids** [#510759].
- **Export paths and filenames** — `/reports/quizzes-taken-by-user.csv/<USERID>` [#1118638].
- **A currency enum** [#1679276, informative] and **an external payment-processor transaction id swapped in the
  response rather than the request** [#1213765].
- **The HTTP method itself**, where protection was applied to one verb only [#2456603, title only].

**Decode everything that looks opaque.** base64, `gid://`, URNs, `vendor-epoch-counter` tokens — the
reporters who decoded found an integer they could increment [#291721 (duplicate), #2633771, #1592587, #1182465].

## I3. Obtaining the id

**An IDOR without a demonstrated acquisition path is a severity downgrade.** Programs said so
explicitly — "exploitation required knowledge of valid project IDs, which limited the practical
impact" [#3219944], and a CVSS scored down for "high attack complexity requiring knowledge of
specific cluster UUIDs" [#3353057]. A duplicate-closure was *contested* on acquisition grounds — "the ID is present in the URLs people
share on social media" — though the program did not reverse it [#2944357].

**Before you try to guess it, check whether it is a secret at all:**
- **Published by the application** — `team_members.json` on the platform itself [#291721, duplicate]; the
  victim's public profile page source [#1592587, #1734639, #1073420]; Workshop page HTML [#365504];
  a public link that carries *both* required ids [#1608735]; the program's own documentation
  [#2487889].
- **Google-indexed URLs** containing complete working query strings [#284963, informative].
- **Chained from a response you're entitled to** — a read endpoint returning *any* user's objects
  **with their internal ids**, feeding a mutation that then accepts the id alone [#1661113]; a
  `getModel` response carrying the version ids a second query consumes [#2528293]; an assignee-picker
  call returning a colleague's UUID [#854290]; a dashboard returning everyone's email and id
  [#1698006]; an endpoint whose only value is minting UUIDs for a *later* attack [#254151].
- **Not validated at all** — a UUID parameter that accepted literally `2` and still minted a valid
  invite [#49499 — closed **informative**, but the *move* costs one request].
  **Try the trivial value before the guessed one.**
- **Structurally weak** — MongoDB ObjectIds are a timestamp + a per-process constant + a counter, so
  holding one collapses the space [#1464168]; an id the reporter *suspected* was timestamp-derived,
  never confirmed [#668439]; a
  hash short enough to attack [#837400]; two related ids that let you *derive then fine-tune*
  [#243943]; a 4-digit × 4-digit pair that is still brute-forceable [#1448550].
- **Plainly sequential** — with the registration response handing you the current high-water mark
  [#685338]. Sequential ids are what turn a single-victim bug into a mass one [#915114, #800608,
  #1048540].
- **Out of band** — a printed card number [#858662, #766437]; reverse-engineered from an APK
  [#3085742]; a third-party lookup service for an external platform id [#990878].

## I4. Oracles that aren't the response body

**The single most damaging assumption is "confirm the response returns B's data".** Counter-examples
are everywhere:

- **`200 OK` with an explicit error.** `{"errors":[{"message":"AsmTag does not exist"}]}` looked like
  a clean negative — the victim's tag was in fact disclosed, visible on the assets page [#2633771].
- **A bare 302.** Proof required logging into store B and looking [#853130]. In another, the
  enforcement *was* a redirect — and the PDF was attached in the redirect body, visible only in a
  proxy [#1085782].
- **Your own response is empty while the victim's is full** — a same-account sanity check reads as
  "feature broken" [#1118638].
- **Write-only IDOR** — the attacker posts into a private thread and provably cannot read the replies
  [#1592596, a plugin CVE].
- **The write errors and the side effect fires anyway** — funds moved despite an error message
  [#766437]; a failed update re-rendered the target object's page complete with Client ID and Secret
  [#1695454].
- **A denied read that still counts** — access refused, group name leaked, license count incremented
  [#879960].
- **Proof by notification** — an email delivered to an arbitrary user about a report they were never
  on [#46397]; a public review appearing on the wrong hacker's profile [#262661].
- **Proof in metadata** — the CSV *header row* enumerated another program's custom-field ids
  [#510759]; an error message carried the last four digits of a stored card [#361984].
- **Proof by inference** — no victim data ever returned; the private object's date range inferred
  from how a filter changed the result set [#663431].
- **A response-length differential** between valid and invalid ids — the reporter's own remediation
  advice ("set the same Length in the response pages") gives the oracle away [#230026]. A
  **content-type/status differential** — a valid image vs "Not found" — does the same job [#2618486, informative].
- **Out-of-band human confirmation** — the reporter could not see the victim's photo, so he recruited
  a consenting manager-account holder and waited for confirmation rather than mass-deleting [#404797].

**Useful tells that an oracle exists:** a write's response echoing the referenced object's
configuration [#1372216] or naming both parties (`createdBy` / `modifiedBy`) [#914331]; an error that
names the *wrong permission for the resource* [#243943]; an error that hands you the value you were
missing, letting you satisfy a precondition [#1372216]; a status field flipping on the victim's side
[#847185]; an "edit" GET returning a populated form, which is a read oracle before you attempt any
write [#52176, #915114].

## I5. Alternate routes, other clients, other hosts

**Assume the enforcement you observed is client-side or gateway-side until you have hit the service
directly.** The corpus shows this asymmetry far more often than the reverse.

- **Enforced on the canonical renderer only** — a private channel denied on the main route but
  rendered by the widget/preview endpoint [#45960]; an unpublished draft redirecting on the HTML
  route while the API returned full JSON [#172545]; a share/preview host that never learned about the
  privacy toggle [#2618486, informative]; a comment section disabled on one item type but open on its sibling
  [#365504]; a WebDAV route ignoring the album ACL [#3518758]; an export route [#1118638]; a
  third-party analytics beacon receiving first-party ids [#1073420].
- **Enforced in the client only** — a capability removed from the UI while the API method still
  works, letting a banned user delete the evidence of their own violation [#2028450]; a rename
  "not allowed" only client-side [#547663].
- **Non-web clients and separate service hosts** — a mobile app hitting a different host that served
  the file with the `Authorization` header **deleted entirely** [#668439]; an acquired app on its own
  domain with its own broken tenancy [#853130]; an API exposing catalog items the web UI hides
  [#344284]; admin endpoints gated only by whether you found `admin.js` [#1489470].
- **Non-production copies** — staging accepting a hardcoded OTP [#715054].
- **Privacy toggles are a map of unenforced controls.** Any "hide this / who can view" setting names
  an object whose secondary renderers probably don't consult it [#2618486, informative].

## I6. Grant-time vs use-time

**A first-class bug class, not a soft-delete trap.** Repeatable test: perform the action, save the
id, then revoke / delete / leave / get banned — and replay.

A deleted DM still returned by id to a third-party OAuth app [#52646] · leaving a group DM not
revoking read access by thread id [#53858] · a photo deleted from an album still served by direct URL
and to a different user [#3518758, not-applicable] · individuals **no longer associated with the organization** still
reading the full member roster [#2381816] · a banned user still deleting their old messages
[#2028450].

## I7. Roles and tenancy within an object

Cross-tenant is the obvious test; **cross-user-within-tenant and lower-role-against-higher-role are
the under-tested ones.** Ownership is not binary — model the role graph inside the object.

A wallet shared with B and C, where B is legitimately on the account (so any "do you have access?"
check passes) but only the owner may revoke shares [#85720] · a low-privileged user creating files
under another user's cluster [#3353057] · a `USER`-role member rewriting the admin's preferences
[#854290] · a *viewer* permanently deleting from an admin's bin [#1074420] · a share recipient
deleting the share [#153905] · Manager-vs-Manager in the same product [#3401612] · a role gate that
fired but tested the **wrong permission** for the resource [#243943] · a role held *somewhere* with
the handler never asking "in which org?" [#1063022, needs a provisioned employee account].

Also: the interesting direction isn't always "read someone else's" — in a family-pairing flow the
valuable case was a *restricted* user removing restrictions imposed on their own account [#1586950].
A two-accounts-swap-the-id method never finds that.

## I8. Transport specifics — GraphQL · gRPC · WebSocket

*The transport never changes the bug; it changes how the object is **named**, how you **address**
the operation, and what the **oracle** looks like. Recovering the contract is a separate job — see
`playbooks/workflows/investigate-graphql.md`, `investigate-grpc.md`, `investigate-api-surface.md`.*

### I8a. GraphQL — corpus-grounded

- **Relay global ids are base64 of `gid://<app>/<Type>/<n>`** — decode, increment, re-encode. A
  campaign id decoded, decremented and re-encoded deleted another program's campaign [#1969141]; the
  same shape on team members [#291721, duplicate], asset tags [#2633771], ML models [#2528293].
- **You can craft ids for object types the UI never showed you**, and the same id may be accepted by
  *several* operations — a query and a mutation both took it [#2207248]. Enumerate every operation
  that accepts the id type, not just the one you captured.
- **Persisted queries** hide the operation behind a hash: the request is
  `{"id":"<hash>","variables":{...}}` and the only attackable surface is the `variables` object
  [#1661113, #1658418].
- **Pagination cursors are the exfiltration multiplier** — looping `hasNextPage`/`endCursor` turned a
  one-page leak into a full dump of any subreddit's mod log [#1658418].
- **Missing authz on one operation implies siblings** — the same gap spanned three endpoints
  [#1137819, #1116387].
- **Mutation arguments are the real surface**, not node-id decoding: a mutation taking `userId`
  alongside the object id [#547663]; a `CreateOrUpdate…` mutation that **destroys** when handed a
  foreign id [#2122671]; a mutation for a feature with **no shipped UI**, found by diffing JS
  [#2218334].

### I8b. gRPC / protobuf — ⚠️ NOT corpus-grounded

*No gRPC IDOR reports were mined for this layer. Everything below is **HYPOTHESIS** derived from the
transport's mechanics, not observed in the corpus — check each against the target before presenting
it as known. It is written here rather than in the lens so that an IDOR hunter finds it.*

- **The oracle is the `grpc-status` trailer, not the HTTP status.** gRPC answers **HTTP 200 with an
  error trailer**, so the usual "200 = it worked" read is wrong in both directions. A
  `PERMISSION_DENIED` / `UNAUTHENTICATED` trailer means authz held. Store the trailer; without it
  you cannot distinguish a successful cross-tenant read from a silent denial.
- **The object reference is a message field**, not a path segment — so §I2's "where references hide"
  applies to the `.proto` message definition. Recover the descriptor first (reflection, mobile app
  bundle, `grpc-web` stubs, repo) or you are fuzzing an opaque binary stream.
- **Per-*service* authz is the characteristic gap.** A connection-level interceptor that
  authenticates once, then lets every method through, is an object-authz bug on every method at
  once — but the `fix_locus` is the *interceptor*, so it is **one** finding, not N. Distinguish that
  from a single method missing its own check, which is its own locus.
- **Transcoding drift is a second door in §I5's sense.** grpc-gateway / Envoy `grpc_json_transcoder`
  exposes the same methods over REST with a different middleware chain. Same id, same identity, two
  edges — if one allows it, that is the alternate route.
- **Streaming vs unary** may be covered by different interceptors; a method denied as unary is worth
  re-trying in its streaming shape.

### I8c. WebSocket — ⚠️ NOT corpus-grounded

*Same caveat: HYPOTHESIS from mechanics, not from mined reports.*

- **Authz at the handshake is not authz per message.** The socket is typically authorized once, on
  upgrade; each subsequent message naming an object may be checked by nobody. That is the same
  "check ran at the wrong point" shape as §I6 (grant-time vs use-time) — the grant happened at
  connect, the use happens per frame.
- **The oracle is asynchronous.** A cross-tenant read may arrive as an unsolicited later frame
  rather than as a reply, so §I4's "oracles that aren't the response body" applies literally —
  capture the whole frame stream, not the response to your message.
- **Subscribe/join messages are the two-object shape** (§I1): you name a channel/room/topic and an
  identity, and only one of them gets checked.
- The socket's own handshake authz and origin check are a different class — `websocket.md`.

## I9. Impact & escalation

**Impact scales with what the object authorizes or controls, not with the sensitivity of the bytes
returned.** Findings where little or no sensitive data was returned: paying with another user's
stored card — the program's own summary states no card information was disclosed [#391092] · expiring
any user's sessions [#56511] · deactivating promos [#264754] · deleting banners [#3401612] · a banned
user destroying evidence of his own violations [#2028450] · unbounded row creation as a DoS
[#1085743] · an endpoint whose only value is as a UUID oracle for a later attack [#254151] · a denied
read that still incremented a billing counter [#879960] · a leaked **username** which, though minor
in itself, was the missing half of a login with no rate limit [#1093908].

**The dominant escalation chain:** profile-write IDOR → change the victim's email → password reset →
full ATO, no interaction [#685338, #950881, #1272478, #1687415 (duplicate), #854290]. Enablers to check: whether
email change requires the old password [#969223], and which field is the actual login identity
[#1272478].

Others: strip parameters until the server errors and leaks the object's credentials, turning a
nuisance into API takeover [#1695454] · cross-user write → stored XSS rendered in the victim's
settings page [#854290] · single read → full-corpus dump via the API's own pagination [#1658418] ·
file IDOR → EXIF GPS coordinates, where the escalation was in the file *content* [#906907] ·
horizontal → vertical, a low-privileged member promoting themselves [#1063022] · overwriting another
org's backups [#1901713].

## I10. False negatives and false positives

**False negatives:**
- The response lies — see **I4** in full.
- **The write silently created a new object on *your* account** instead of editing the victim's; the
  victim's object is unchanged and the real finding (unbounded row creation) is on your side of the
  fence [#1085743].
- **The reference may appear in two places** — the URL *and* the `Referer` header, both of which the
  reporter changed [#1085743]; a single-field swap risks a false negative.
- **You swapped the wrong identity field** [#1272478].
- **Precondition-gated writes** — a cross-user upload that succeeded *only* when the victim's slot
  was still empty; testing against a populated object reads as "not vulnerable" [#1196976].
- **Handshake-only flows** — a bug that lived in a multi-step session handshake and was initially
  irreproducible for triage; single-request Repeater testing misses these [#1966006].
- **Plan/tier gating** — a free account yielded only a partial primitive; the full takeover needed the
  team tier's "Move to another user" feature [#915127].

**False positives:**
- **Mixed-tenant responses** — an invoice PDF showing *your* name alongside *the victim's* email and
  address. "It shows my name, so it's my data" is a false negative on a confirmed finding — read
  every field [#2207248].
- **Not an IDOR at all** — checkout price tampering with no object reference [#1403176]; client-side
  DOM editing that the server merely relays [#2322663].
- **Attributability matters.** A cross-account read of a random-hash object was closed as *not a
  vulnerability* because the returned data could not be tied to an identity [#966949, informative]. If you cannot
  show attribution, build the attribution step — a second endpoint mapping id → user — before
  submitting. The counterweight: an "unguessable" hash was accepted precisely because it was **too
  short** [#837400], so test the entropy rather than assuming it is a control.

## I11. Novelty and duplication

**Treat "obvious `?id=` on a mainstream program is always a dup" with caution.** Straightforward
identifier swaps are still present in this corpus on serious estates: an unauthenticated
`Download.aspx?id=` serving contracts and PII [#1626508] · `filepush/ftp/<id>/` serving FTP
credentials [#228383] · a plain path id expiring any user's sessions on a major platform [#56511] ·
a filter array accepting a foreign id [#663431]. And one report was closed as a duplicate and then
**reopened, validated and resolved** [#2965357] — a dup label is not always final.

Two honest caveats: most of the *high-profile* findings here are not plain query ids at all but
GraphQL mutations, encoded references and body parameters; and the corpus files carry no resolution
state, so acceptance can't be read off them.

The real predictor of freshness is **how much traffic that specific host and feature has seen**:
unreleased features whose backend is live and whose UI is CSS-hidden [#2218334] · features shipped
weeks ago [#2618486, informative, #1644436] · legacy endpoints the app no longer calls, found by reversing the APK
[#3085742] · regional and country deployments of the same brand [#701160, #766437] · acquired apps on
their own domains [#853130] · gov/telco/enterprise estates [#1626508, #228383, #1272478].

Dup risk is genuinely higher on high-traffic consumer flows — what differentiates an accepted report
there is a **demonstrated acquisition path plus a demonstrated action**.

## I12. Validation ethics

These are repeatable techniques, not manners, and several reporters used them to get findings
accepted without touching a stranger's data:

- **Seed your own records into the wordlist** so a brute-force demonstration only ever hits objects
  you created [#230026].
- **Create the victim object yourself and set it explicitly private**, so triage needs no second
  account provisioned [#2528293]. Where the product is open source, build and seed it locally instead
  of testing against production [#1848176].
- **Ask a consenting participant** before altering their object [#291721, duplicate], or — to avoid damaging
  production data you cannot see — have a consenting account holder confirm the effect [#404797].
- **Ask the program for a test reference** when you cannot obtain one [#391092].
- **Throttle** — one reporter held Intruder to 3 [#1592587].
- **Probe the boundary, don't dump** — "record 60000 returns nothing, so ~50000 are accessible"
  sizes the impact without harvesting [#1489470].
- **Disclose accidents.** One reporter reported that a decrement had likely changed a real user's
  email and asked the program to remediate that specific account [#685338]; another halted after
  pulling one stranger's record and said so [#1048540]; another apologised for two researchers being
  emailed [#46397].

## I13. Worked examples

**A. Two-object verb.** A "move this item to another folder" call carrying `item_id` (yours) and
`folder_id`. *Model:* two nouns, one check. *Oracle first (§3):* the item's absence from your list and
its presence in B's — decide this before swapping. *Test:* keep `item_id`, change only `folder_id` to
B's. *Acquisition:* is B's folder id published anywhere — a share link, a profile page, a prior
response? *fix_locus =* "move handler validates the item but never joins the destination folder to
the caller."

**B. Client-asserted identity.** A profile-save POST carrying a hidden `userId` alongside the session.
*Model:* the presence of that field is the finding. *Test:* change it to B's id and set an email you
control. *Oracle:* B's own session, plus whether a password reset now reaches your inbox — but check
first which field is the app's real login identity [#1272478]. *Stop:* prove it on your own second
account, never a stranger's [#685338].

**C. Route with a rule, and its sibling.** You observe a restriction — a private album, a disabled
comment box, "you left this group". *Model:* a rule exists, so enumerate every route that reaches the
same object: API vs HTML, widget/preview, export, mobile host, WebDAV, third-party beacon (**I5**).
*Test:* replay the saved id on each. *Oracle:* the object rendering where it shouldn't. *fix_locus =*
the specific route that skipped the check — and check its siblings before you file.
