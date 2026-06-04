# ADVERSA — Run Guide (Mac M4 / Apple Silicon)

A single document covering: setup on Mac M4, how to choose what to scan,
and how to drive the interactive wizard end-to-end.

---

## At a glance — four commands

```bash
./run.sh setup     # one time
./run.sh start     # boot the API server
./run.sh app       # open the interactive wizard
./run.sh stop      # shut down when done
```

Everything below explains those four lines in detail, plus the bit
nobody tells you: **what to actually type when the wizard asks
`Targets [127.0.0.1]:`**.

---

# Part 1 · One-time setup on Mac M4

## Step 1.1 — Install Homebrew (skip if you have it)

On Apple Silicon, Homebrew lives at `/opt/homebrew`:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Add brew to your shell (zsh on M4 by default)
echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
source ~/.zprofile
```

Verify:

```bash
which brew      # should print /opt/homebrew/bin/brew
brew --version
```

## Step 1.2 — Install Node.js (≥ 20) and Go

```bash
brew install node go
```

Verify:

```bash
node -v         # v20.x or newer
go version      # go1.21+
```

## Step 1.3 — Install the scanner tools

The pipeline uses four scanners. Missing tools aren't fatal — that
stage is skipped — but the full pipeline needs all four.

```bash
# nmap — service / version probe
brew install nmap

# libpcap — required by naabu on Mac
brew install libpcap

# naabu — fast port discovery
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# nuclei — CVE / template scanning
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Make Go binaries reachable
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.zprofile
source ~/.zprofile

# testssl.sh — TLS / SSL audit
git clone https://github.com/drwetter/testssl.sh ~/testssl.sh
sudo ln -s ~/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
```

> If `naabu` complains about pcap at runtime, on M4 it's usually because
> it can't find the Homebrew pcap. Run with:
> ```bash
> sudo DYLD_LIBRARY_PATH=/opt/homebrew/lib naabu -version
> ```

Verify everything:

```bash
naabu -version
nmap --version
nuclei -version
testssl.sh --version
```

## Step 1.4 — Set up the project

```bash
cd "/Users/rutikmangale/Documents/DRIVE T -Var/Security-projects/Intrynx/adversa"
./run.sh setup
```

This runs `npm install` and creates `.env.local` with auto-generated
JWT secrets.

## Step 1.5 — Paste your Anthropic API key

Open `.env.local` and fill in the empty key:

```
ANTHROPIC_API_KEY=sk-ant-api03-...
```

This unlocks the AI commentary, attack-path analysis, and AI report.
Without it, scans still run — you just get no `▸` AI lines.

## Step 1.6 — Sanity check

```bash
./run.sh check
```

You want:
- ✓ Node, npm
- ✓ ANTHROPIC_API_KEY / AUTH_SECRET / SCOPE_SECRET / AGENT_SECRET
- ✓ node_modules
- ✓ or ⚠ on each scanner (warnings are OK — that stage just skips)

---

# Part 2 · How to find what to scan

This is the question people stall on. When the wizard prompts:

```
? Targets [127.0.0.1]:
```

…what do you type? It depends entirely on **what you have permission
to scan**. There are four answers, ranked by safety.

## Option A · Localhost — always safe

```
127.0.0.1
```

This scans only your Mac itself, on the loopback interface. No packets
leave your machine. Always allowed. Great for the first run.

**What you'll find:** whatever's listening on your Mac.
- macOS itself usually exposes nothing externally
- If you have Docker Desktop running, you may see its ports
- If you run a local dev server (Next.js on 3000, Postgres on 5432),
  those will appear

Check what your Mac is listening on before scanning:

```bash
sudo lsof -i -nP -sTCP:LISTEN
```

## Option B · Spin up deliberate lab targets

The clearest way to see ADVERSA work is to give it something with
known vulnerabilities. Run vulnerable-by-design containers:

```bash
# DVWA — classic vulnerable web app
docker run --rm -d --name dvwa -p 8080:80 vulnerables/web-dvwa

# An old SSH with a real CVE
docker run --rm -d --name vuln-ssh -p 2222:22 vulhub/openssh:CVE-2018-15473

# A WAF / web target stack
docker run --rm -d --name hackazon -p 8443:443 mutzel/all-in-one-hackazon
```

(Install Docker Desktop first: `brew install --cask docker`)

Then in the wizard:

```
? Targets [127.0.0.1]: 127.0.0.1
```

…and ADVERSA will find DVWA on 8080, the vulnerable SSH on 2222, and
testssl will probe 8443.

Stop the containers when done:

```bash
docker stop dvwa vuln-ssh hackazon
```

## Option C · Your own Mac on the local network

If you want ADVERSA to scan **your own laptop** from its LAN address
(rather than loopback) — different attack surface, sometimes
different findings:

Find your Wi-Fi IP:

```bash
ipconfig getifaddr en0      # Wi-Fi IP, e.g. 192.168.1.42
ipconfig getifaddr en1      # if you have Ethernet
```

Then type that IP at the prompt:

```
? Targets [127.0.0.1]: 192.168.1.42
```

You're still only scanning yourself — just over the network interface
instead of loopback. Safe.

## Option D · An authorized network (read this carefully)

ADVERSA is built to scan internal networks for VAPT engagements.
But scanning a network you don't own — your home Wi-Fi included if
other people's devices are on it (roommates, family, IoT, printers,
the ISP modem) — can crash devices, trip IDS, and is in many
jurisdictions illegal without explicit authorization.

**Only put a LAN range into the prompt if:**

- [ ] You own every device on the range, OR
- [ ] You have written authorization from each device's owner, OR
- [ ] It's a dedicated lab network with no production / personal devices

If those are true, here's how to identify the range and live hosts.

### Find your LAN range

```bash
# Your IP and subnet on Wi-Fi
ifconfig en0 inet

# Example output:
# inet 192.168.1.42 netmask 0xffffff00 broadcast 192.168.1.255
#                          └─ /24 (255.255.255.0)

# Default gateway (your router)
route -n get default | grep gateway
```

Mask `0xffffff00` = `/24`. So your LAN range is `192.168.1.0/24`.

### See who's actually online

```bash
# Hosts your Mac has talked to recently
arp -a

# Active mDNS / Bonjour discovery
dns-sd -B _services._dns-sd._udp local.
```

### Then enter the range or specific IPs

```
? Targets [127.0.0.1]: 192.168.1.42,192.168.1.43,192.168.1.50
```

…or a CIDR:

```
? Targets [127.0.0.1]: 192.168.1.0/24
```

Start narrow. `/24` scans up to 254 hosts; that's a lot of packets
and a lot of findings.

---

# Part 3 · Run it

## Step 3.1 — Start the server

```bash
./run.sh start
```

Wait for `✓ Server up at http://localhost:3000`. Logs stream to
`.adversa-server.log` — `tail -f .adversa-server.log` in another tab
if anything misbehaves.

## Step 3.2 — Launch the wizard

```bash
./run.sh app
```

You see the banner. If you've never logged in, it prompts:

```
? Email: you@yourorg.com
[DEV] OTP: 482917            ← printed because no email service configured
? Enter code: ******
✓ Authenticated as you@yourorg.com [admin]
```

The first user to ever log in **automatically becomes admin**. No
extra step.

## Step 3.3 — Pick "Run a scan"

```
Choose an action
  1) Run a scan              naabu → nmap → nuclei → testssl + AI commentary
  2) View findings
  3) Ask the AI
  4) Generate AI report
  5) Manage engagements
  6) Scan status
  7) Admin — user management
  8) Log out
  9) Exit
? Choose 1–9 [1]: 1
```

The wizard now walks you through every field:

```
? How will you provide targets?
  1) Type them here    comma-separated IPs / CIDRs / hostnames
  2) Read from a file
? Choose 1–2 [1]: 1

? Targets [127.0.0.1]: 127.0.0.1          ← see Part 2 for what to put here

? Scan profile
  1) Fast        naabu + nuclei         ~minutes
  2) Standard    naabu + nmap + nuclei  recommended
  3) Deep        all tools + testssl    thorough
? Choose 1–3 [1]: 2

? Stealth level (1 = quiet, 9 = fast) [5]: 5
? Persist findings to data/findings.json? (Y/n): y
? Enable AI commentary during scan? (Y/n): y
? Tag this scan to an engagement? (y/N): n

Review
  Targets:    127.0.0.1
  Profile:    standard
  Stealth:    5/9
  Save:       yes
  AI:         yes

? Start scan? (Y/n): y
```

Watch the live output:
- `[Port Scanner] ✓ 1 host(s) with open ports`
- `▸ <Claude's narration of what that stage found>` ← only if AI is on
- Individual `[HOST]` and `[CRITICAL] ... ` lines as findings stream
- `└─ <Claude explaining a specific finding>` per finding
- `AI Attack Path Analysis` at the end with 2-3 suggested next moves

---

# Part 4 · After the scan

When the scan finishes, the wizard asks `Return to main menu?` →
**Yes**. From there:

| Menu pick | What it does |
|---|---|
| **View findings** | Table, filter by severity / host, or drill into one finding's full evidence |
| **Ask the AI** | Streaming Q&A with the current findings as context. Empty line returns to menu. |
| **Generate AI report** | Pick an engagement, choose which sections (executive summary, scorecard, roadmap, etc.), export to terminal or JSON |
| **Manage engagements** | Create one to tag future scans, list, or show detail |
| **Scan status** | Recent scans with their state |
| **Admin** | (admin only) add operators, scope them to specific CIDRs, remove them |

To leave for the day, pick **Exit** (9), then:

```bash
./run.sh stop
```

---

# Part 5 · Cheat sheet

```bash
# Setup (once)
./run.sh setup
./run.sh check

# Daily use
./run.sh start
./run.sh app
./run.sh stop

# Logs
tail -f .adversa-server.log

# Power user — skip the wizard, run a one-shot
./run.sh cli scan 127.0.0.1 --profile standard --save
./run.sh cli findings --severity critical
./run.sh cli ask "summarize the top risks"
```

---

# Part 6 · Troubleshooting

| What you see | What it means | Fix |
|---|---|---|
| `Could not reach the server.` | The API server isn't running | `./run.sh start`, wait for `✓ Server up` |
| `<email> is not authorized.` | You aren't the first user and nobody added you | Ask the admin to use Admin → Add a user |
| `403 — target out of scope` | The admin scoped you narrower than your target | Admin → Change scope, or pick a target inside your scopes |
| No `▸` AI lines appear | `ANTHROPIC_API_KEY` is blank | Paste it into `.env.local`, then `./run.sh stop && ./run.sh start` |
| `[Port Scanner] ✗ not found` | naabu missing or not on PATH | Re-do Step 1.3; `which naabu` should print a path |
| `naabu: ... libpcap ...` | M4 can't find Homebrew's libpcap | `sudo DYLD_LIBRARY_PATH=/opt/homebrew/lib naabu ...`, or `brew reinstall libpcap` |
| nmap stage finds nothing on LAN | macOS isn't allowing raw ICMP/SYN without sudo | Run the server from a sudo-able terminal, or stick to `-sT` (already the default) |
| Wizard says no engagements | You haven't created one yet | Menu → Manage engagements → Create |
| OTP never arrives | No `RESEND_API_KEY` is set | Look at the CLI output — dev mode prints the OTP right there in green |
| `EADDRINUSE :3000` | Something else is on port 3000 | `lsof -i :3000` to find it, kill it, or change `PORT` in `.env.local` |

---

# Part 7 · M4-specific notes

- Homebrew lives at `/opt/homebrew/bin`, not `/usr/local/bin`. If
  scripts can't find tools, double-check your `PATH` includes the
  former.
- Go binaries from `go install` land in `~/go/bin`. Add to `PATH`.
- naabu uses libpcap — install with `brew install libpcap`. The Mac
  one is fine.
- nuclei templates auto-download on first run (`~/.config/nuclei/templates`).
  First scan may pause for ~30 seconds while that fetches.
- testssl.sh is a bash script — works natively on M4.
- Docker Desktop for Mac on M4 runs containers under a Linux VM
  (Rosetta or native). Both work for the lab targets in Part 2.B.
- macOS's firewall may prompt for permission the first time naabu or
  nmap sends raw packets. Allow it.

---

# Part 8 · Quick rule of thumb

| Goal | Target |
|---|---|
| "I just want to see the wizard work" | `127.0.0.1` |
| "I want to see real CVE findings" | Spin up DVWA / vulnerable Docker container (Part 2.B) then `127.0.0.1` |
| "I want to scan my own Mac over the LAN" | `ipconfig getifaddr en0` → that IP |
| "I'm running an authorized engagement" | The CIDRs in the engagement's scope |

That's the entire flow: setup once, pick a target you're allowed to
scan, run the wizard.
