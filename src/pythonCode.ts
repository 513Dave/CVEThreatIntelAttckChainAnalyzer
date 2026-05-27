export const pythonScriptContent = `import tkinter as tk
from tkinter import messagebox, ttk
import urllib.request
import json
import threading
import re
import ctypes

# Enable High-DPI font rendering on modern Windows systems
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass

# Custom visual palette
BG_COLOR = "#0D1117"
PANEL_BG = "#161B22"
BORDER_COLOR = "#30363D"
TEXT_COLOR = "#E6EDF2"
TEXT_MUTED = "#8B949E"

# Threat Priority Colors
COLOR_CRITICAL = "#F85149"
COLOR_HIGH = "#F0883E"
COLOR_MEDIUM = "#D29922"
COLOR_LOW = "#3FB950"
COLOR_BLUE = "#58A6FF"

# Pre-packaged local curated high-fidelity threat intelligence profiles
CURATED_INTEL = {
    "CVE-2021-44228": {
        "name": "Log4Shell",
        "actors": ["Lazarus Group (APT38)", "APT41", "Volt Typhoon", "LockBit", "Clop", "Cozy Bear (APT29)"],
        "industries": ["Critical Infrastructure", "Finance", "Healthcare", "Government", "Technology"],
        "countries": ["Global (US, UK, Germany, Canada, Australia)"],
        "chain_type": "execution",
        "exploitChainNote": "Provides instant deep shell execution. Frequently chained downstream with auth bypass vulnerabilities to compromise firewalled internal nodes."
    },
    "CVE-2022-30190": {
        "name": "Follina",
        "actors": ["Fancy Bear (APT28)", "Cozy Bear (APT29)", "Kimsuky"],
        "industries": ["Government", "Defense", "Education", "Media", "Acrospace"],
        "countries": ["Ukraine", "United States", "United Kingdom", "Germany", "Poland"],
        "chain_type": "initial_access",
        "exploitChainNote": "Bypasses sandboxes via diagnostics tool loops. Can escalate fast when paired with secondary localized user execution tools."
    },
    "CVE-2021-34473": {
        "name": "ProxyShell",
        "actors": ["LockBit", "BlackCat (ALPHV)", "APT41", "Volt Typhoon", "Hafnium"],
        "industries": ["Critical Infrastructure", "Government", "Finance", "Education", "Legal Operations"],
        "countries": ["United States", "Japan", "Germany", "Global Scope"],
        "chain_type": "initial_access",
        "exploitChainNote": "A massive remote auth bypass gateway. Attackers leverage this to run commands with SYSTEM-level privileges immediately on target exchange nodes."
    },
    "CVE-2023-34362": {
        "name": "MOVEit Transfer RCE",
        "actors": ["Clop Ransomware Group"],
        "industries": ["Finance", "Healthcare", "Government", "Legal", "Technology Services", "Logistics"],
        "countries": ["United States", "United Kingdom", "Canada", "Germany", "Netherlands"],
        "chain_type": "initial_access",
        "exploitChainNote": "SQL injection enabling unauthorized backend file retrieval. Often combined with local privilege escalation toolkits to control server virtual machines."
    },
    "CVE-2023-4966": {
        "name": "Citrix Bleed",
        "actors": ["LockBit 3.0", "BlackCat (ALPHV)", "State-Sponsored threat actors"],
        "industries": ["Finance Operations", "Public Sector", "Healthcare Services", "Critical Infrastructure"],
        "countries": ["United States", "Japan", "Australia", "United Kingdom", "Singapore"],
        "chain_type": "auth_bypass",
        "exploitChainNote": "Enables passive active-session key extraction over public network segments, bypasses multi-factor authentication (MFA) safeguards."
    }
}

# Regex scanning rules for dynamic threat intelligence harvesting
ACTORS = {
    "Lazarus Group (APT38)": ["lazarus", "apt38", "hidden cobra"],
    "Fancy Bear (APT28)": ["fancy bear", "apt28", "sofacy", "strontium"],
    "Cozy Bear (APT29)": ["cozy bear", "apt29", "nobelium", "midnight blizzard"],
    "Volt Typhoon": ["volt typhoon", "bronze silhouette"],
    "Sandworm": ["sandworm", "voodoo bear", "blackenergy"],
    "LockBit Ransomware": ["lockbit"],
    "BlackCat / ALPHV": ["blackcat", "alphv"],
    "Clop Ransomware": ["clop", "cl0p"],
    "APT41 (Double Dragon)": ["apt41", "barium", "wicked panda", "hafnium"],
    "Kimsuky": ["kimsuky", "velvet chollima"]
}

INDUSTRIES = {
    "Government": ["government", "federal", "ministry", "state department", "public sector"],
    "Defense": ["defense", "military", "aerospace", "army", "navy", "air force"],
    "Critical Infrastructure": ["energy", "water utility", "utility grid", "power generator", "telecommunications", "transportation"],
    "Finance": ["financial services", "banking", "cryptocurrency exchange", "insurance company", "payment processor"],
    "Healthcare": ["healthcare system", "medical clinic", "hospital", "pharmaceuticals"],
    "Education": ["educational institute", "academy", "university", "faculty"],
    "Technology Services": ["it company", "software publisher", "cloud platform", "saas", "tech sector"]
}

COUNTRIES = {
    "United States": ["united states", "us", "usa", "american"],
    "United Kingdom": ["united kingdom", "uk", "british", "london"],
    "Ukraine": ["ukraine", "ukrainian", "kyiv"],
    "Germany": ["germany", "german", "germanic"],
    "Taiwan": ["taiwan", "taiwanese", "taipei"],
    "Japan": ["japan", "japanese", "tokyo"],
    "South Korea": ["south korea", "republic of korea", "seoul"],
    "Australia": ["australia", "australian", "canberra"],
    "Canada": ["canada", "canadian", "ottawa"]
}

def fetch_json_sync(url, timeout=7):
    """Dependency-free synchronous HTTP requester."""
    req = urllib.request.Request(
        url, 
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatIntelAnalyzerLocal/1.0'}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception:
        return None

def lookup_cve_details(cve_id):
    """Heuristic fallback chain: CIRCL API -> Backup Mock Database"""
    cve_upper = cve_id.strip().upper()
    url = f"https://cve.circl.lu/api/cve/{cve_upper}"
    data = fetch_json_sync(url)
    if data and 'id' in data:
        return {
            "id": data.get("id"),
            "summary": data.get("summary", "No description profile provided by authority."),
            "cvss": float(data.get("cvss", 0.0)),
            "cwe": data.get("cwe", "N/A"),
            "references": data.get("references", [])
        }
    
    # Empty schema fallback
    return {
        "id": cve_id,
        "summary": "Vulnerability metadata lookup bypassed or offline. Local heuristic scoring applied.",
        "cvss": 0.0,
        "cwe": "N/A",
        "references": []
    }

def fetch_epss_score(cve_id):
    """Retrieve Exploit Prediction Score"""
    url = f"https://api.first.org/data/v1/epss?cve={cve_id.strip().upper()}"
    data = fetch_json_sync(url)
    if data and 'data' in data and len(data['data']) > 0:
        item = data['data'][0]
        return {
            "epss": float(item.get("epss", 0.0)),
            "percentile": float(item.get("percentile", 0.0))
        }
    return {"epss": 0.0, "percentile": 0.0}

def analyze_single_cve(cve_id):
    cve_upper = cve_id.strip().upper()
    details = lookup_cve_details(cve_upper)
    epss = fetch_epss_score(cve_upper)
    
    actors, industries, countries = set(), set(), set()
    chain_type = "other"
    exploit_chain_note = "Local signature analysis scans did not register distinct chain triggers."

    # 1. Evaluate Curated signatures
    if cve_upper in CURATED_INTEL:
        curated = CURATED_INTEL[cve_upper]
        for a in curated["actors"]: actors.add(a)
        for i in curated["industries"]: industries.add(i)
        for c in curated["countries"]: countries.add(b if type((b := c)) is str else str(b))
        chain_type = curated["chain_type"]
        exploit_chain_note = curated["exploitChainNote"]
    else:
        # 2. Heuristics text scan matches
        scan_text = (details["summary"] + " " + " ".join(details["references"])).lower()
        for group, patterns in ACTORS.items():
            if any(p in scan_text for p in patterns):
                actors.add(group)
        for ind, patterns in INDUSTRIES.items():
            if any(p in scan_text for p in patterns):
                industries.add(ind)
        for cy, patterns in COUNTRIES.items():
            if any(p in scan_text for p in patterns):
                countries.add(cy)

        # Infer chaining profiles
        entry_patterns = ["bypass", "authentication bypass", "cross-site", "directory traversal", "file upload", "sql injection"]
        exec_patterns = ["remote code execution", "rce", "arbitrary code execution", "deserialization", "command injection"]
        priv_patterns = ["privilege", "privilege escalation", "local privilege"]

        if any(p in scan_text for p in entry_patterns) or "CWE-287" in details["cwe"] or "CWE-22" in details["cwe"]:
            chain_type = "initial_access"
            exploit_chain_note = "Acts as an initial gateway. Enables remote attackers to compromise the boundary segment."
        elif any(p in scan_text for p in exec_patterns) or "CWE-94" in details["cwe"] or "CWE-78" in details["cwe"]:
            chain_type = "execution"
            exploit_chain_note = "Delivers local command shell capabilities. Extremely dangerous when chained downstream from directory exposure bugs."
        elif any(p in scan_text for p in priv_patterns) or "CWE-269" in details["cwe"]:
            chain_type = "privilege_escalation"
            exploit_chain_note = "Allows low-privileged local shells to elevate permissions to administrator/SYSTEM privileges."

    # Final defaults
    if not actors: actors.add("Opportunistic Ransomware Affiliates")
    if not industries: industries.add("All Verticals / General Sectors")
    if not countries: countries.add("Global / Open Target Geography")

    return {
        "id": cve_upper,
        "details": details,
        "epss": epss,
        "intel": {
            "threatActors": list(actors),
            "industriesTargeted": list(industries),
            "countriesTargeted": list(countries),
            "chainingType": chain_type,
            "exploitChainNote": exploit_chain_note
        }
    }

def process_attack_chains(results):
    chains = []
    entry_nodes = [r for r in results if r["intel"]["chainingType"] in ["initial_access", "auth_bypass"]]
    execution_nodes = [r for r in results if r["intel"]["chainingType"] in ["execution", "privilege_escalation"]]

    for entry in entry_nodes:
        for exec_n in execution_nodes:
            if entry["id"] != exec_n["id"]:
                chains.append(
                    f"⚠️ ATTACK CHAIN IDENTIFIED:\\n• Phase 1: Exploit {entry['id']} ({entry['intel']['chainingType']}) to gain boundary landing.\\n• Phase 2: Pivot locally and exploit {exec_n['id']} ({exec_n['intel']['chainingType']}) to achieve remote code execution and full target domain compromise."
                )
    return chains

class LocalThreatIntelApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CVE Intel & Attack Chain Analyzer")
        self.geometry("1100x750")
        self.configure(bg=BG_COLOR)
        
        self.cisa_kev_cache = {}
        self._setup_ui()
        
        self.update_status("Contacting CISA to index latest Known Exploited Vulnerabilities catalog...")
        threading.Thread(target=self._async_load_cisa_kev, daemon=True).start()

    def _setup_ui(self):
        # Configure grid weightings
        self.columnconfigure(0, weight=4, minsize=380)
        self.columnconfigure(1, weight=6, minsize=500)
        self.rowconfigure(1, weight=1)

        # Header Title
        lbl_head = tk.Frame(self, bg="#101827", height=65)
        lbl_head.grid(row=0, column=0, columnspan=2, sticky="ew")
        lbl_head.grid_propagate(False)
        
        tk.Label(
            lbl_head, 
            text="CVE INTELLIGENCE & ATTACK DAISY CHAIN ANALYZER", 
            fg="#FFFFFF", 
            bg="#101827", 
            font=("Segoe UI", 12, "bold")
        ).pack(anchor="w", padx=15, pady=8)
        
        tk.Label(
            lbl_head, 
            text="Windows Desktop Portable Edition • Connected to CIRCL & FIRST.org API endpoints", 
            fg=TEXT_MUTED, 
            bg="#101827", 
            font=("Segoe UI", 8, "italic")
        ).pack(anchor="w", padx=15, pady=0)

        # --- LEFT PANEL: ENTRY & METRICS ---
        panel_left = tk.Frame(self, bg=PANEL_BG, bd=1, relief="solid", highlightbackground=BORDER_COLOR)
        panel_left.grid(row=1, column=0, sticky="nsew", padx=15, pady=15)
        panel_left.columnconfigure(0, weight=1)
        panel_left.rowconfigure(2, weight=1)

        # 1. Input Section
        lbl_label = tk.Label(panel_left, text="vulnerability entries (one per line):", fg=TEXT_COLOR, bg=PANEL_BG, font=("Segoe UI", 10, "bold"))
        lbl_label.grid(row=0, column=0, sticky="w", padx=15, pady=(15, 5))

        self.input_box = tk.Text(panel_left, height=7, bg="#0D1117", fg="#FFFFFF", insertbackground="white", relief="flat", highlightthickness=1, highlightbackground=BORDER_COLOR)
        self.input_box.insert("1.0", "CVE-2023-4966\\nCVE-2021-44228")
        self.input_box.grid(row=1, column=0, sticky="ew", padx=15, pady=5)

        self.btn_execute = tk.Button(
            panel_left, 
            text="ANALYZE RISK", 
            bg=COLOR_BLUE, 
            fg="#FFFFFF", 
            relief="flat", 
            activebackground="#1f6feb", 
            font=("Segoe UI", 10, "bold"), 
            command=self.start_analysis_thread
        )
        self.btn_execute.grid(row=2, column=0, sticky="ew", padx=15, pady=10)

        # 2. Risk priority aggregated display
        inner_badge = tk.Frame(panel_left, bg="#0D1117", bd=1, relief="solid", highlightbackground=BORDER_COLOR)
        inner_badge.grid(row=3, column=0, sticky="nsew", padx=15, pady=(5, 15))
        inner_badge.columnconfigure(0, weight=1)

        tk.Label(inner_badge, text="AGGREGATED PRIORITY SCORE", fg=TEXT_MUTED, bg="#0D1117", font=("Segoe UI", 8, "bold")).grid(row=0, column=0, pady=(10, 2))
        
        self.priority_badge = tk.Label(inner_badge, text="UNASSESSED", fg=TEXT_MUTED, bg="#0D1117", font=("Arial Black", 24, "bold"))
        self.priority_badge.grid(row=1, column=0, pady=5)

        self.reason_box = tk.Text(inner_badge, bg="#0D1117", fg=TEXT_MUTED, font=("Segoe UI", 9), relief="flat", wrap="word", height=6)
        self.reason_box.grid(row=2, column=0, sticky="nsew", padx=10, pady=10)
        self.reason_box.config(state="disabled")

        # --- RIGHT PANEL: DETAILED REPORT VIEW ---
        panel_right = tk.Frame(self, bg=PANEL_BG, bd=1, relief="solid", highlightbackground=BORDER_COLOR)
        panel_right.grid(row=1, column=1, sticky="nsew", padx=(0, 15), pady=15)
        panel_right.columnconfigure(0, weight=1)
        panel_right.rowconfigure(1, weight=1)

        tk.Label(panel_right, text="vulnerability threat dossiers & intel:", fg=TEXT_COLOR, bg=PANEL_BG, font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w", padx=15, pady=15)

        self.report_display = tk.Text(panel_right, bg="#0D1117", fg=TEXT_COLOR, insertbackground="white", relief="flat", highlightthickness=1, highlightbackground=BORDER_COLOR, wrap="word")
        self.report_display.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))

        # Text tags for color-coded formatted outputs
        self.report_display.tag_config("critical", foreground=COLOR_CRITICAL, font=("Segoe UI", 10, "bold"))
        self.report_display.tag_config("high", foreground=COLOR_HIGH, font=("Segoe UI", 10, "bold"))
        self.report_display.tag_config("medium", foreground=COLOR_MEDIUM, font=("Segoe UI", 10, "bold"))
        self.report_display.tag_config("sect", foreground=COLOR_BLUE, font=("Segoe UI", 10, "bold"))
        self.report_display.tag_config("muted", foreground=TEXT_MUTED)

        # Status Footer
        self.status_bar = tk.Label(self, text="Sync state: Idle", bg="#161B22", fg=TEXT_MUTED, font=("Segoe UI", 8), anchor="w", bd=1, relief="sunken")
        self.status_bar.grid(row=2, column=0, columnspan=2, sticky="ew")

    def update_status(self, text):
        self.status_bar.config(text=f"Sync state: {text}")

    def _async_load_cisa_kev(self):
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        data = fetch_json_sync(url, timeout=10)
        if data and "vulnerabilities" in data:
            for v in data["vulnerabilities"]:
                cve = v.get("cveID", "").strip().upper()
                if cve:
                    self.cisa_kev_cache[cve] = {
                        "name": v.get("vulnerabilityName", "Unknown"),
                        "date": v.get("dateAdded", "Unknown"),
                        "action": v.get("requiredAction", "Patch system immediately.")
                    }
            self.update_status(f"CISA Database online. Loaded {len(self.cisa_kev_cache)} exploits successfully.")
        else:
            self.update_status("CISA API offline or timed out. Defaulting to local offline fallback engine.")

    def start_analysis_thread(self):
        text = self.input_box.get("1.0", tk.END)
        cves = re.findall(r"CVE-\\d{4}-\\d{4,9}", text, re.I)
        cve_list = list(set([c.upper().strip() for c in cves]))
        
        if not cve_list:
            messagebox.showwarning("Input Alert", "No valid CVE ID found in input. Format must match: CVE-YYYY-NNNN")
            return

        self.btn_execute.config(state="disabled")
        self.update_status("Querying intelligence feeds, please wait...")
        threading.Thread(target=self._run_analytical_engine, args=(cve_list,), daemon=True).start()

    def _run_analytical_engine(self, cve_list):
        analyzed_items = []
        for index, cve_id in enumerate(cve_list):
            self.update_status(f"Querying [{cve_id}] ({index + 1}/{len(cve_list)})...")
            res = analyze_single_cve(cve_id)
            # Cross reference CISA KEV
            if cve_id in self.cisa_kev_cache:
                res["kev"] = self.cisa_kev_cache[cve_id]
            else:
                res["kev"] = None
            analyzed_items.append(res)
            
        self.after(0, self._render_results, analyzed_items)

    def _render_results(self, results):
        self.btn_execute.config(state="normal")
        self.update_status("Threat intelligence aggregation completed.")

        # Wipe output displays
        self.report_display.config(state="normal")
        self.report_display.delete("1.0", tk.END)

        # Extract values
        max_cvss = max([r["details"]["cvss"] for r in results]) if results else 0.0
        has_kev = any([r["kev"] is not None for r in results])
        chains = process_attack_chains(results)

        for res in results:
            cve = res["id"]
            cvss = res["details"]["cvss"]
            cwe = res["details"]["cwe"]
            summary = res["details"]["summary"]
            epss = res["epss"]
            intel = res["intel"]
            kev_data = res["kev"]

            # Output individual report
            self.report_display.insert(tk.END, f"Vulnerability Dossier: {cve}\\n", "sect")
            
            sev_tag = "muted"
            if cvss >= 9.0: sev_tag = "critical"
            elif cvss >= 7.0: sev_tag = "high"
            elif cvss >= 4.0: sev_tag = "medium"
            
            self.report_display.insert(tk.END, f"• CVSS Base Score: {cvss} ", "muted")
            self.report_display.insert(tk.END, f"({sev_tag.upper()})\\n", sev_tag)
            self.report_display.insert(tk.END, f"• CWE Category Linked: {cwe}\\n", "muted")
            self.report_display.insert(tk.END, f"• Exploit Probability (EPSS): {epss['epss']:.3%} (Percentile: {epss['percentile']:.1%})\\n", "muted")
            
            if kev_data:
                self.report_display.insert(tk.END, f"• CISA KEV Exploitation: YES (Designated: {kev_data['date']})\\n", "critical")
                self.report_display.insert(tk.END, f"  Required mitigation: {kev_data['action']}\\n", "critical")
            else:
                self.report_display.insert(tk.END, "• CISA KEV Exploitation: NO\\n", "muted")

            # Dynamic intel targets
            self.report_display.insert(tk.END, "• Target Landscape & Threat actor profiling:\\n", "muted")
            self.report_display.insert(tk.END, f"  - Known threat actors: {', '.join(intel['threatActors'])}\\n", "muted")
            self.report_display.insert(tk.END, f"  - Targeted industries: {', '.join(intel['industriesTargeted'])}\\n", "muted")
            self.report_display.insert(tk.END, f"  - Geographical scope: {', '.join(intel['countriesTargeted'])}\\n", "muted")
            self.report_display.insert(tk.END, f"• Exploit Chaining Dynamics: {intel['exploitChainNote']}\\n", "sect")
            self.report_display.insert(tk.END, "-" * 60 + "\\n\\n")

        # Update Aggregated Priority Score
        priority = "LOW"
        color = COLOR_LOW
        assessment_note = "Submitted targets hold standard risks with low localized threat indices."

        if any([r["details"]["cvss"] >= 9.0 or (r["kev"] is not None) for r in results]) or len(chains) > 0:
            priority = "CRITICAL"
            color = COLOR_CRITICAL
            if len(chains) > 0:
                assessment_note = "Extremely high threat! System identified conditions enabling initial edge access vulnerabilities to daisy chain directly with command execution exploits."
            else:
                assessment_note = "Critically high risk! Verified zero-day vulnerability profiles or CISA KEV list matches detected in catalog search."
        elif max_cvss >= 7.0 or has_kev:
            priority = "HIGH"
            color = COLOR_HIGH
            assessment_note = "Elevated exposure threat. Vulnerabilities have mature exploitation paths or active wild campaigns."
        elif max_cvss >= 4.0:
            priority = "MEDIUM"
            color = COLOR_MEDIUM
            assessment_note = "Standard localized risk profiles. Resolve during routine secure code maintenance deployment intervals."

        self.priority_badge.config(text=priority, fg=color)
        
        # Write reasoning
        self.reason_box.config(state="normal")
        self.reason_box.delete("1.0", tk.END)
        self.reason_box.insert(tk.END, f"Risk Context:\\n{assessment_note}\\n\\n")
        if chains:
            self.reason_box.insert(tk.END, "\\n".join(chains))
        self.reason_box.config(state="disabled")

        self.report_display.config(state="disabled")

if __name__ == "__main__":
    app = LocalThreatIntelApp()
    app.mainloop()
`;
