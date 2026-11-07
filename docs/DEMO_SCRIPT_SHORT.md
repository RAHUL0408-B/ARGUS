# ARGUS - 4-Minute Demo Video Script

Team: Binary Builders - Pawan Singh Bhandari & Rahul Bramhankar

**Before recording:** run one full assessment end-to-end first (ask Claude to re-run
`lab_init.ps1`, then run a request through the UI) so Findings and the Report are
already populated when you start recording. You are narrating a real, completed run
- not waiting on a live scan on camera.

---

## 0:00-0:15 - Intro (no screen needed yet)

> "Hi, we're Binary Builders. This is ARGUS - an AI agent that runs real penetration
> tests and writes the report itself."

## 0:15-0:40 - The request (type it live)

- Type: `Assess the lab network 10.77.0.0/24 for web application vulnerabilities. No denial of service.`
- Click **Check scope and make a plan**.

> "It checks the target is actually authorized before doing anything."

## 0:40-1:05 - The plan

- Point at 2 steps in the plan and their reasons.

> "Every step comes with a reason - it's not a fixed script, it's deciding."

## 1:05-1:30 - Findings tab

- Click **Findings**.

> "Multiple tools reporting the same bug get merged into one finding, not duplicates."

- Click into one finding, point at confidence + evidence.

## 1:30-1:55 - A refuted finding

- Click a refuted finding.

> "This looked real, ARGUS double-checked it, and ruled it out itself."

## 1:55-2:20 - Risk ranking

- Click top finding, scroll to the priority score.

> "Risk isn't a guess - every factor in this score is shown."

## 2:20-2:50 - The safety gate

- Go to **Approvals** tab.

> "Anything that actively tests a bug - not just looks - waits for a human here. That's the safety rule."

- Type name, click **Approve**.

## 2:50-3:20 - The real finding

- Go back to **Findings**, show the SQLi or XSS result.

> "That's a real SQL injection, found live on our test target - not staged."

## 3:20-3:50 - The report

- **Report** tab -> **Download PDF** -> scroll it fast (summary, findings table,
  limitations page).

> "It all becomes one client-ready report - honest about limitations too."

## 3:50-4:00 - Close

> "That's ARGUS. Thank you."

---

## If something goes wrong on camera

- **A scan seems stuck:** cut it in editing, or talk over it using the architecture
  slide from the deck.
- **A tool shows "unavailable":** say "that's a safety feature - if a tool fails,
  ARGUS reports the gap honestly instead of hiding it," then move on.
