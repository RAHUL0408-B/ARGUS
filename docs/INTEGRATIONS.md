# Integration status matrix

Labels follow the hackathon rule: **Live** = ARGUS runs the tool and parses its real output. **Import-only** = ARGUS parses an exported file you provide; it does not run the tool. **Planned** = not implemented. **Unsupported** = deliberately not offered.

The UI **Tools** tab (`GET /api/matrix`) probes this at runtime.

| Tool | Status | How it is used | Limits |
|---|---|---|---|
| nmap | **Live** | `docker exec argus-tools nmap` for service discovery (`-sV`) and NSE http enumeration; XML parsed. | No `vulners` script. CVE hints come only from a small reference table (`KNOWN_VULNERABLE_VERSIONS`) and are labelled version-only. |
| Nikto | **Live** | Run in `argus-tools` (cloned from upstream), JSON output parsed. | Reports no CVSS or severity. ARGUS derives a coarse severity from the message and marks it derived. |
| OWASP ZAP | **Live** | ZAP daemon API (spider plus passive scan; active scan only after approval, capped at 4 minutes). | No CVSS from ZAP, none invented. Alert fetch capped at 500. |
| Metasploit | **Live, approval-gated** | `docker run metasploitframework/metasploit-framework ./msfconsole -x "use <module>; ..."` for allow-listed **read-only auxiliary** modules (http_version, http_header, options, robots_txt, ftp_version, ssh_version). | No exploit modules, no payloads, never autonomous. Large image. |
| Nessus | **Import-only** | Parses `.nessus` XML exports. Hosts outside scope are dropped. Informational plugins are context. | Commercial product. No live API is implemented or claimed. |
| Burp Suite | **Import-only** | Parses Burp XML issue exports. | Burp Pro REST API is **Planned**, not implemented. |
| OpenVAS / GVM | **Import-only** | Parses OpenVAS XML reports. | Live GMP integration is **Planned**. |
| Claude planner | **Optional, untested** | Ranks code-generated candidates when `ANTHROPIC_API_KEY` is set; falls back to rules. | No API key was available to the team, so this path has not been run. |
| Exploit frameworks (beyond read-only checks) | **Unsupported** | - | By design. |

## Notes on samples

`samples/sample_nessus_dvwa.nessus`, `sample_burp_dvwa.xml` and `sample_openvas_dvwa.xml` are synthetic files we wrote to test the parsers and cross-tool correlation. They are labelled `SAMPLE-` when imported and must not be presented as real scanner output. Replace with real exports when available.

## Known data limits

- The CISA KEV snapshot in `reference.py` is partial and offline. Exploitability x1.3 is applied only to entries it contains.
- CVSS is shown only when a tool reported it; otherwise priority uses a labelled severity midpoint.
