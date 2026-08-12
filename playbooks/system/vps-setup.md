# VPS Setup / Bootstrap (one-time per VPS)

Run this once when the human first provides a VPS. Confirm each step's output before
moving on (evidence discipline applies to setup too — don't assume an install
succeeded, verify the binary runs). Record completion + tool versions in the target
gitignored `config.json`. Record only the remote working directory and tool readiness in
`index.md` under **VPS**.

Assume a fresh Debian/Ubuntu x86_64 VPS with root or sudo. Adjust for the actual
distro you find (`cat /etc/os-release` first).

---

## 0. Verify access & host

```
$(tools/config.py ssh) 'whoami && cat /etc/os-release && nproc && free -h && df -h /'
```

## 1. Base packages

```
sudo apt-get update && sudo apt-get install -y \
  git curl wget jq unzip tmux build-essential python3 python3-pip python3-venv \
  libpcap-dev whois dnsutils
```

## 2. Go — one version, and it must satisfy the newest tool

```
GO_VERSION=1.25.0        # pius needs >= 1.25; pin to the highest any tool below requires
cd /tmp && curl -fsSLO "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
  && sudo rm -rf /usr/local/go \
  && sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
grep -q '/usr/local/go/bin' ~/.bashrc || \
  echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
go version    # must print go${GO_VERSION} or newer
```

> **The version is a dependency, not a preference.** This used to pin 1.22.5 and then install a
> tool requiring 1.25 — `go install` fails with a version error most of the way through the run,
> after everything before it has already succeeded. Pin to the highest requirement, and re-check
> before adding a tool.

## 3. Recon toolchain

Tool choices track `playbooks/system/recon-toolkit.md`. **Nothing here suppresses an error** — a
tool that fails to install must say so now, not silently at 3am inside a phase.

**ProjectDiscovery suite (via `pdtm`):**
```
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
pdtm -install-all   # subfinder, dnsx, naabu, httpx, katana, nuclei, tlsx, cdncheck,
                    # asnmap, mapcidr, alterx, notify, interactsh-client, ...
```

**Other Go tools** — `@latest` is deliberate for actively maintained tools; pin only where a
version is known-good:
```
set -e
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/gf@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/owasp-amass/amass/v5/...@master        # v5 has no tagged release yet
go install github.com/ffuf/ffuf/v2@latest
go install github.com/d3mondev/puredns/v2@latest             # needs massdns (below)
go install github.com/sensepost/gowitness@latest             # needs Chrome/Chromium
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
go install github.com/denandz/sourcemapper@latest
go install github.com/j3ssie/metabigor@latest
go install github.com/PentestPad/subzy@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
go install github.com/praetorian-inc/pius/cmd/pius@latest    # requires Go >= 1.25
set +e
```

**massdns** (compiled — `puredns` needs the binary on `$PATH`):
```
git clone https://github.com/blechschmidt/massdns.git /tmp/massdns \
  && make -C /tmp/massdns && sudo cp /tmp/massdns/bin/massdns /usr/local/bin/
```

**apt:**
```
sudo apt-get install -y nmap masscan feroxbuster chromium-browser
```

**WhatWeb — upstream release, not the Ubuntu 0.6.3 package:**
```
mkdir -p "$HOME/tools" "$HOME/.local/bin"
if [ ! -d "$HOME/tools/whatweb/.git" ]; then
  git clone --depth 1 --branch v0.6.4 https://github.com/urbanadventurer/WhatWeb.git \
    "$HOME/tools/whatweb"
fi
if [ ! -e "$HOME/.local/bin/whatweb" ] && [ ! -L "$HOME/.local/bin/whatweb" ]; then
  ln -s "$HOME/tools/whatweb/whatweb" "$HOME/.local/bin/whatweb"
fi
"$HOME/.local/bin/whatweb" --version
```

> Ubuntu's `whatweb` 0.6.3 package can install the launcher in `/usr/bin` while its
> `require_relative` paths still look for `/usr/bin/lib/*`, producing a Ruby `LoadError`. Prefer
> the self-contained upstream release and confirm the login shell resolves `~/.local/bin/whatweb`.

**Python — pipx first, and it is not installed by default:**
```
sudo apt-get install -y pipx && pipx ensurepath && export PATH="$PATH:$HOME/.local/bin"
pipx install bbot
for p in uro arjun wafw00f waymore git-dumper clairvoyance graphw00f s3scanner; do
  pipx install "$p" || echo "FAILED: $p"
done
```

> **`pipx`, not `pip3 install --user`.** Ubuntu 23.04+ marks the system Python
> externally-managed and refuses `--user` installs outright (PEP 668). pipx also isolates each
> tool, so one dependency conflict does not take out the rest.

**TruffleHog — the v3 binary, not the PyPI package:**
```
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
  | sudo sh -s -- -b /usr/local/bin
trufflehog --version    # must be v3.x
```

> `pip3 install trufflehog` installs an **unrelated, abandoned v2 package**. Every command in this
> workspace assumes v3 syntax (`trufflehog filesystem …`, `trufflehog git …`), which v2 does not
> have. This is the single most likely first-install failure.

**Release binaries** (no package manager): `gitleaks`, `noseyparker`, `x8`.

**Community nuclei templates aggregator (optional, vet before running):**
```
go install github.com/xm1k3/cent@latest && cent init
```

## 3b. Verify capabilities before you trust them

Install failures are quiet; a phase that calls a missing tool is not. Run this inventory, but judge
capabilities rather than demanding every alternative: `x8` or Arjun can satisfy parameter
discovery; ffuf or feroxbuster can satisfy content discovery. A named tool still must be installed
before the model selects it.

```
for t in subfinder dnsx naabu httpx katana nuclei tlsx asnmap mapcidr alterx \
         anew gf gau amass ffuf puredns gowitness jsluice sourcemapper metabigor \
         subzy dalfox grpcurl pius massdns nmap masscan feroxbuster whatweb \
         bbot uro arjun wafw00f waymore git-dumper s3scanner trufflehog gitleaks \
         flock jq; do
  command -v "$t" >/dev/null || echo "MISSING: $t"
done
go version; python3 --version; trufflehog --version 2>&1 | head -1
```

> `tools/monitor.py enable` and `tools/sweep.py` run their own prerequisite checks and refuse
> rather than scheduling a job that fails silently every 12 hours. This shell list is a transparent
> inventory: a missing named tool is acceptable when an installed alternative covers the skill,
> but a missing whole capability must be resolved before relying on it.

## 4. Nuclei templates

```
nuclei -update-templates
```

## 5. Wordlists

```
mkdir -p ~/wordlists && cd ~/wordlists
git clone --depth 1 https://github.com/danielmiessler/SecLists.git

# assetnote: the LISTS ARE NOT IN THE GIT REPO. `git clone assetnote/wordlists` fetches the
# source of the wordlists.assetnote.io *website* — docs and CSS, zero wordlists — and leaves a
# ~/wordlists/assetnote/ directory that looks provisioned and is useless. Fetch the files:
mkdir -p ~/wordlists/assetnote && cd ~/wordlists/assetnote
curl -O https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt   # 141 MB, ~9M lines
curl -O https://wordlists-cdn.assetnote.io/data/manual/2m-subdomains.txt       #  29 MB
# Common quick picks:
#   SecLists/Discovery/DNS/dns-Jhaddix.txt                      (2.17M — good default brute list)
#   SecLists/Discovery/DNS/subdomains-top1million-110000.txt
#   SecLists/Discovery/Web-Content/raft-large-directories.txt
#   SecLists/Discovery/Web-Content/api/api-endpoints.txt
```

**Assert it before a phase depends on it** — a wordlist path that does not exist makes a brute
run report a confident zero:

```sh
for w in ~/wordlists/assetnote/best-dns-wordlist.txt \
         ~/wordlists/SecLists/Discovery/DNS/dns-Jhaddix.txt; do
  [ -s "$w" ] && printf '  ok   %8d  %s\n' "$(wc -l < "$w")" "$w" || printf '  MISSING       %s\n' "$w"
done
```

## 6. Resolvers (for fast DNS)

```
mkdir -p ~/wordlists/resolvers
wget -O ~/wordlists/resolvers/resolvers.txt \
  https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
```

## 7. Per-target working dirs

```
$(tools/config.py ssh) 'mkdir -p ~/targets/<target>/{raw/{subdomains,dns,ports,http,urls,content,js,nuclei,snapshots},jobs,logs,loot}'
# jobs/ = the phase scripts you run · logs/ = their tee'd output · loot/ = artifacts
# Nothing a job produces belongs in ~ — see vps-execution.md.
```

## 7b. Deploy HunterStick itself — without this, `run.py` cannot wrap anything

`tools/run.py` is what turns a command into a **reproducible** one: tool version, redacted argv
plus a hash of the real one, sha256 of every input file, host, duration, exit code, and the
artifact's size and hash — written to `logs/exec/`. It judges success on the **artifact**, not on
what the tool printed, so an `ffuf` that exits 0 and leaves an empty file is reported as the
failure it is.

It no longer validates scope, rate or method. That policy engine was ~310 lines and it was
deleted deliberately: command correctness belongs to the model (`skills/shared/_recon-method.md` — read
the installed binary's help, pilot, verify the output shape, adapt), and scope is the hunter's
(`AGENTS.md` §*Scope is the hunter's*). **A recorder that always runs beats a validator that never
did** — and that validator never did: `logs/exec/` held zero records for an entire engagement.

Skip this deployment and every remote command is unwrapped: no reproducibility record at all. That
is not hypothetical — a whole engagement ran that way before anyone noticed the checkout was
missing.

```sh
# from the workspace root, on your laptop
rsync -az --exclude '__pycache__' --exclude '*.pyc' tools/ <vps>:~/hunterstick/tools/
rsync -az --exclude '__pycache__'                    playbooks/ <vps>:~/hunterstick/playbooks/
```

`run.py` writes into a target brain, so the target needs an `index.md` on the VPS (that is the one
file it checks to confirm it is a brain — it does **not** read `scope.md`, and there is no marker
file any more; those were the old policy engine). Create the per-target dir up there:

```sh
ssh <vps> 'mkdir -p ~/targets/<t>' && scp targets/<t>/index.md <vps>:~/targets/<t>/
```

Then **verify the deployed recorder matches this checkout** — the whole point, and the one command
that catches a stale VPS:

```sh
tools/vps-sync.py verify-runner        # MATCH, or MISMATCH/ABSENT with the redeploy line
```

It exits non-zero on drift, so a wrapper stops rather than trusting a record written by code you did
not deploy. **Re-run the rsync (and `verify-runner`) after changing anything in `tools/`.** The VPS
copy is a deployment, not a mount; a local fix does not reach a running VPS by itself.

---

## 8. Verify

```
for t in subfinder dnsx naabu httpx katana nuclei tlsx cdncheck asnmap mapcidr alterx \
         puredns massdns gau waymore uro anew gf ffuf feroxbuster whatweb wafw00f \
         gowitness jsluice trufflehog gitleaks arjun x8 nmap masscan grpcurl dalfox \
         subzy interactsh-client; do \
  printf '%s: ' "$t"; command -v "$t" || echo MISSING; done
```

Record the results + versions in the target `index.md`. Any MISSING tool → install
before relying on the phase that needs it.

Then verify the repository and deployed recorder from the laptop:

```sh
python3 tools/self-check.py
python3 tools/graph.py --check
python3 -m unittest discover -s tests
tools/vps-sync.py verify-runner
```

The inventory above verifies the external binaries and required data assets. The local commands
verify the repository contracts and compare the deployed `run.py` hash with this checkout. A
missing whole capability, required data asset, or mismatched recorder is a failure; a missing
alternative is a warning.

---

## API keys (optional, boosts passive sources)

Keys live in **`config.json`** (`api_keys.*`) at the workspace root — one place, gitignored,
never in a target folder and never on the VPS in plaintext you might snapshot.

```sh
cp config.example.json config.json && chmod 600 config.json   # then fill it in
tools/config.py check                                          # presence, never values
```

To push them to a VPS tool that wants its own config file, render it from the source of
truth rather than retyping — e.g. subfinder's `~/.config/subfinder/provider-config.yaml`.
**Never commit keys, never echo them into a log, a report, or the transcript.** A missing
key degrades passive coverage; it must never turn into a silent zero — the phase says which
source it could not query.

### amass wants the same keys in its own file — and will ignore them three different ways

**Do this once per VPS**, not per target: amass reads `~/.config/amass/config.ini`, and a
workspace with keys configured only for subfinder runs amass blind. Measured on a real estate:
**9,012 subdomains without keys, 55,298 with them** — same binary, same apex, keys present in
`config.json` the whole time.

```ini
[data_sources]
minimum_ttl = 1440

[data_sources.Shodan]
[data_sources.Shodan.Credentials]
apikey = <from config.json>
```
Repeat the three-line block per source. `chmod 600` the file.

**Three silent-failure modes, all of which look like a correct config:**

1. **The binary may not read the file at all.** Some builds do *not* auto-load
   `~/.config/amass/config.ini` — every key is ignored no matter how correct the file is.
   Pass it explicitly: `amass enum -passive -d <apex> -config ~/.config/amass/config.ini`.
2. **Not every source takes a bare `apikey`.** ZoomEye wants `username`/`password` in v3,
   Censys wants `api_id`/`secret`, FOFA wants `email`/`key`. Writing `apikey` for these is
   accepted by the parser and ignored by the source.
3. **Not every subfinder provider exists in amass.** `bevigil` and `netlas` have no amass
   equivalent at all — there is nothing to write.

**Verify rather than assume — `amass enum -list` is the oracle, not the config file:**

```sh
amass enum -list | grep -E '^(Shodan|GitHub|Chaos|VirusTotal|FullHunt|ZoomEye)\b'
amass enum -config ~/.config/amass/config.ini -list | grep -E '^(Shodan|GitHub|Chaos|VirusTotal|FullHunt|ZoomEye)\b'
```

A trailing `*` means the source is available. Diff the two: any source without a `*` in the
second listing has a key that is present and **inert**. That check is the only thing that
distinguishes a working config from a plausible one — it is how the ZoomEye case above was
found, after the config had already been declared correct.
