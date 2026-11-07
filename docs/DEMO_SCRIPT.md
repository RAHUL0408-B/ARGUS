# ARGUS demo script - for recording the video

Follow this top to bottom. Each step says what to click, what to say (you can read it almost word for word), and what you should see happen. If something on screen doesn't match "What you'll see," stop and ask me before continuing - don't improvise past a mismatch.

**Before you start recording:**
1. Make sure the app is running: open a terminal and ask me "is the server and lab up?" - I'll check and tell you.
2. Open `http://localhost:8765` in your browser. Full-screen the browser window.
3. Have this script open on a second screen or printed, so you're not reading it on camera.

---

## 1. Introduce it (30 seconds, no screen needed yet)

> "Hi, we're Team ARGUS. We built a conversational AI agent for penetration testing - it takes a plain-English request, runs real security tools, figures out what's actually a risk, and writes a professional report. A human approves anything risky before it happens. Let me show you."

## 2. Make a request and show scope checking

- Click the big text box at the top. Type: `Assess the lab network 10.77.0.0/24 for web application vulnerabilities. No denial of service.`
- Click **Check scope and make a plan**.

**Say:** "I just asked it in plain English. Before it does anything, it checks this is a target we're actually allowed to test - it refuses anything outside an authorized list by default."

**What you'll see:** A plan appears, listing which hosts are in scope and which tools it intends to run, each with a one-line reason.

## 3. Show the plan and approve it

**Say:** "Every step it's about to take comes with its reasoning written out - not just 'running nmap,' but why nmap, right now."

- Scroll through the plan briefly, pointing at one or two of the reasons shown.
- Click **Approve plan**.

**What you'll see:** The **Live activity** panel starts filling in with jobs running (nmap, then Nikto/ZAP). This takes a few minutes - you can speed this part up in editing, or talk over it live.

## 4. While it runs - narrate what's happening

**Say (anytime during the wait):** "It's not just running every tool blindly. It looks at what it's already found, and decides what to check next based on that - that's the 'agent' part, not a fixed script."

Optional: open the **Decisions** / activity feed and point at one entry that shows multiple options it considered, not just the one it picked.

## 5. Findings - merged duplicates and a refuted false positive

Once it reaches "review" status (watch the status badge at the top):

- Click the **Findings** tab.

**Say:** "Here's the result. Each one of these has been checked by more than one source where possible, and duplicates from different tools get merged into a single entry instead of showing you the same problem four times."

- Click into one finding. Point out: the **confidence level** (Low/Medium/High), the **evidence** (raw tool output, with a hash so it can't be silently altered), and the **status** (observed / validated / refuted).
- If a refuted finding is visible, click it and say: "This one looked like a real issue at first, but ARGUS actually tested it with one harmless request and confirmed it wasn't - so it's marked refuted, not just deleted."

## 6. Risk ranking

**Say:** "Findings aren't just listed - they're ranked, and the ranking is a formula you can actually read."

- Click into the top finding, scroll to the priority/risk section.
- Point at the factors shown (base severity, exposure, confidence) and say: "Every number here is sourced - nothing is a model just guessing a score."

## 7. Human approval - the important safety moment

- Go to the **Approvals** tab (there should be a pending ZAP active scan or similar waiting).

**Say:** "This is the key safety rule: anything that actively tests a vulnerability - not just observes it - stops here and waits for a human. Nothing intrusive runs without this."

- Type your name as the analyst, click **Approve**.

**What you'll see:** The approved scan runs (takes 1-2 minutes). When it finishes, go back to **Findings** and show a **SQL Injection** or **Cross-site scripting** finding that appeared - this is a real vulnerability found live on the practice target, not staged.

**Say:** "That's a real SQL injection vulnerability, found live, just now, on our practice target."

## 8. The report

- Go to the **Report** tab, click **Download PDF**.
- Open the downloaded PDF. Scroll through quickly: executive summary, methodology, findings table, one detailed finding, the limitations section at the end.

**Say:** "And it all rolls up into one client-ready report - executive summary for a manager, full technical detail for an engineer, and an honest limitations section that says what wasn't tested and what's an assumption, not just the good news."

## 9. Close

**Say:** "That's ARGUS - a plain-English request to a professional VAPT report, with a human approving every risky step along the way, and nothing shown to you today that wasn't a real, live result. Thank you."

---

## If something goes wrong on camera

- **A scan seems stuck / slow:** this is normal, real tools take real time. Talk about the architecture (use slide 5 of the deck) while it finishes, or cut this part in editing.
- **A tool shows "unavailable" or fails:** say "this is actually a good demonstration of a safety feature - if a tool fails, ARGUS keeps going and reports the gap honestly instead of crashing or hiding it," then move on.
- **You get lost in the UI:** message me what you're seeing and I'll tell you exactly what to click.

## Plain-language cheat sheet for narration

(See `docs/PROJECT_OVERVIEW.md` section 2 for the full glossary if a judge asks a term you don't recognize.)

- **Finding** = one specific weakness ARGUS believes it found.
- **Scope** = the list of targets we're allowed to test.
- **Live vs. import-only** (tool status) = "live" means ARGUS actually runs that tool itself; "import-only" means we read a report file from that tool rather than running it live (true for Nessus, Burp, OpenVAS - commercial tools we don't have licenses to run live).
- **SQLi / XSS** = two of the most common, serious web security bugs - the thing you want the demo to actually find.
