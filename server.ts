import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI, Type } from "@google/genai";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json());

// Initialize CISA KEV Database Storage
let cisaKevDatabase: Record<string, any> = {};
let cisaDatabaseLoaded = false;
let cisaDatabaseError: string | null = null;

// Download CISA KEV Catalog on Startup
async function loadCisaKevCatalog() {
  try {
    console.log("Fetching CISA KEV catalog...");
    const res = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
    if (!res.ok) {
      throw new Error(`CISA returned status ${res.status}`);
    }
    const data = await res.json();
    if (data && Array.isArray(data.vulnerabilities)) {
      const db: Record<string, any> = {};
      for (const item of data.vulnerabilities) {
        if (item.cveID) {
          db[item.cveID.toUpperCase().trim()] = {
            vulnerabilityName: item.vulnerabilityName || "Unknown",
            dateAdded: item.dateAdded || "Unknown",
            requiredAction: item.requiredAction || "No action specified",
            dueDate: item.dueDate || "N/A",
            knownRansomwareCampaignUse: String(item.knownRansomwareCampaignUse).toLowerCase() === "known" || String(item.knownRansomwareCampaignUse).toLowerCase() === "yes",
            notes: item.notes || ""
          };
        }
      }
      cisaKevDatabase = db;
      cisaDatabaseLoaded = true;
      console.log(`CISA KEV catalog successfully loaded: ${Object.keys(db).length} entries.`);
    } else {
      throw new Error("Invalid structure returned by CISA KEV Feed.");
    }
  } catch (error: any) {
    cisaDatabaseError = error.message;
    console.error("Failed to load CISA KEV Catalog:", error);
  }
}

// Lazy/Safe init for Gemini API to prevent crash if key is missing on startup
let aiClient: GoogleGenAI | null = null;
function getAiClient(): GoogleGenAI | null {
  if (!aiClient) {
    const key = process.env.GEMINI_API_KEY;
    if (!key) {
      console.warn("GEMINI_API_KEY environment variable is not defined. Secure AI search fallback enabled.");
      return null;
    }
    aiClient = new GoogleGenAI({
      apiKey: key,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        }
      }
    });
  }
  return aiClient;
}

// Fetch CVSS / CWE / Summary from CIRCL public CVE API
async function fetchCveDetails(cveId: string) {
  try {
    const url = `https://cve.circl.lu/api/cve/${cveId.toUpperCase().trim()}`;
    const response = await fetch(url, { headers: { 'Accept': 'application/json' } });
    if (!response.ok) {
      throw new Error(`CIRCL API responded with status ${response.status}`);
    }
    const data = await response.json();
    if (data && data.id) {
      return {
        id: data.id,
        summary: data.summary || "No summary details available.",
        cvss: typeof data.cvss === "number" ? data.cvss : (parseFloat(data.cvss) || 0.0),
        cwe: data.cwe || "N/A",
        references: Array.isArray(data.references) ? data.references : []
      };
    }
  } catch (err) {
    console.warn(`Failed to retrieve CVE details from CIRCL for ${cveId}, trying fallback or empty...`, err);
  }

  // Backup fallback placeholder
  return {
    id: cveId,
    summary: "Detailed vulnerability details could not be parsed dynamically. Relying on intelligence heuristic engine.",
    cvss: 0.0,
    cwe: "N/A",
    references: []
  };
}

// Fetch Exploit Prediction Score (EPSS) from FIRST.org API
async function fetchEpssScore(cveId: string) {
  try {
    const url = `https://api.first.org/data/v1/epss?cve=${cveId.toUpperCase().trim()}`;
    const response = await fetch(url);
    if (response.ok) {
      const body = await response.json();
      if (body?.data && Array.isArray(body.data) && body.data.length > 0) {
        const item = body.data[0];
        return {
          epss: typeof item.epss === "number" ? item.epss : parseFloat(item.epss || "0"),
          percentile: typeof item.percentile === "number" ? item.percentile : parseFloat(item.percentile || "0")
        };
      }
    }
  } catch (err) {
    console.warn(`EPSS lookup failed for ${cveId}:`, err);
  }
  return { epss: 0.0, percentile: 0.0 };
}

// Local Curated DB for instantly stable high-quality results
const CURATED_INTEL: Record<string, {
  name: string;
  actors: string[];
  industries: string[];
  countries: string[];
  chain_type: string;
  exploitChainNote: string;
}> = {
  "CVE-2021-44228": {
    name: "Log4Shell",
    actors: ["Lazarus Group (APT38)", "APT41", "Volt Typhoon", "LockBit", "Clop", "Cozy Bear (APT29)"],
    industries: ["Critical Infrastructure", "Finance", "Healthcare", "Government", "Technology"],
    countries: ["Global (United States, United Kingdom, Germany, Canada, Australia)"],
    chain_type: "execution",
    exploitChainNote: "This vulnerability delivers instant post-auth remote code execution (RCE). It acts as a powerful downstream secondary action after attackers bypass gates, or can be exploited directly if logs are exposed externally on entry endpoints."
  },
  "CVE-2022-30190": {
    name: "Follina",
    actors: ["Fancy Bear (APT28)", "Cozy Bear (APT29)", "Kimsuky", "Storm-0978"],
    industries: ["Government", "Defense", "Education", "Media", "Critical Infrastructure"],
    countries: ["Ukraine", "United States", "United Kingdom", "Germany", "Poland"],
    chain_type: "initial_access",
    exploitChainNote: "This initial access vulnerability leverages malicious document files to run diagnostics tools without authentication, letting hackers easily chain it with user land privilege scalers to seize deep lateral access."
  },
  "CVE-2021-34473": {
    name: "ProxyShell",
    actors: ["LockBit", "BlackCat (ALPHV)", "APT41", "Volt Typhoon", "Hafnium"],
    industries: ["Critical Infrastructure", "Government", "Finance", "Education", "Legal"],
    countries: ["United States", "Japan", "Germany", "Global"],
    chain_type: "initial_access",
    exploitChainNote: "Acting as an authenticated bypass entry gateway, ProxyShell enables external actors to execute server commands without system keys. This is extremely hazardous when combined with local privilege escalation bugs like PrintNightmare."
  },
  "CVE-2023-34362": {
    name: "MOVEit Transfer RCE",
    actors: ["Clop Ransomware Group"],
    industries: ["Finance", "Healthcare", "Government", "Legal", "Technology", "Logistics"],
    countries: ["United States", "United Kingdom", "Canada", "Germany", "Netherlands"],
    chain_type: "initial_access",
    exploitChainNote: "This initial access SQL injection bypasses standard authentications. Attackers chain this to establish custom web shells and dump active files securely from database nodes without raising local perimeter alarms."
  },
  "CVE-2023-4966": {
    name: "Citrix Bleed",
    actors: ["LockBit 3.0", "BlackCat (ALPHV)", "State-Sponsored Actors"],
    industries: ["Finance", "Government", "Healthcare", "Critical Infrastructure", "Industrial"],
    countries: ["United States", "Japan", "Australia", "United Kingdom", "Singapore"],
    chain_type: "auth_bypass",
    exploitChainNote: "A severe auth bypass vulnerability letting threat actors steal ongoing active session keys over remote portals, letting them hijack active user credentials and chain with privilege scaling tools to control Active Directory."
  }
};

// Heuristic Threat Intelligence lookup fallback (regex parsing / pattern matching)
function guessThreatIntelHeuristics(cveId: string, summary: string): any {
  const cveUpper = cveId.toUpperCase().trim();
  const summaryLower = summary.toLowerCase();

  // Pick up curated details instantly
  if (CURATED_INTEL[cveUpper]) {
    const curated = CURATED_INTEL[cveUpper];
    return {
      threatActors: curated.actors,
      industriesTargeted: curated.industries,
      countriesTargeted: curated.countries,
      chainingType: curated.chain_type,
      exploitChainNote: curated.exploitChainNote
    };
  }

  // Common pattern categories
  const actors = new Set<string>();
  const industries = new Set<string>();
  const countries = new Set<string>();

  // Regex rules
  if (summaryLower.includes("lazarus") || summaryLower.includes("apt38")) actors.add("Lazarus Group (APT38)");
  if (summaryLower.includes("apt28") || summaryLower.includes("fancy bear")) actors.add("Fancy Bear (APT28)");
  if (summaryLower.includes("apt29") || summaryLower.includes("cozy bear") || summaryLower.includes("nobelium")) actors.add("Cozy Bear (APT29)");
  if (summaryLower.includes("volt typhoon")) actors.add("Volt Typhoon");
  if (summaryLower.includes("lockbit")) actors.add("LockBit Ransomware");
  if (summaryLower.includes("alphv") || summaryLower.includes("blackcat")) actors.add("BlackCat / ALPHV Ransomware Group");
  if (colorsMatch(["china", "chinese", "hafnium", "apt41"], summaryLower)) actors.add("Chinese State-Sponsored APT Groups (APT41/Hafnium)");
  if (colorsMatch(["russia", "russian", "sandworm", "turla"], summaryLower)) actors.add("Russian State Cyber Threat Actors");
  if (colorsMatch(["north korea", "korean", "kimsuky"], summaryLower)) actors.add("North Korean State-Sponsored APT Groups");

  if (colorsMatch(["government", "federal", "state", "ministry"], summaryLower)) industries.add("Government & Public Services");
  if (colorsMatch(["military", "defense", "weapon", "aerospace"], summaryLower)) industries.add("Defense & Military Contractors");
  if (colorsMatch(["finance", "bank", "crypto", "payment", "transaction"], summaryLower)) industries.add("Financial Institutions");
  if (colorsMatch(["health", "hospital", "pharma", "medical"], summaryLower)) industries.add("Healthcare & Pharmaceuticals");
  if (colorsMatch(["energy", "utility", "infrastructure", "electricity", "grid", "power", "water"], summaryLower)) industries.add("Critical Infrastructure & Energy");
  if (colorsMatch(["software", "cloud", "saas", "technology", "enterprise"], summaryLower)) industries.add("Technology & IT Providers");

  if (colorsMatch(["united states", "us", "usa", "american"], summaryLower)) countries.add("United States");
  if (colorsMatch(["united kingdom", "uk", "british", "england"], summaryLower)) countries.add("United Kingdom");
  if (colorsMatch(["ukraine", "kyiv", "ukrainian"], summaryLower)) countries.add("Ukraine");
  if (colorsMatch(["germany", "german", "europe"], summaryLower)) countries.add("Germany");
  if (colorsMatch(["taiwan", "taipei", "taiwanese"], summaryLower)) countries.add("Taiwan");
  if (colorsMatch(["japan", "tokyo", "japanese"], summaryLower)) countries.add("Japan");

  // Fallbacks if set remains empty
  if (actors.size === 0) actors.add("Opportunistic Cybercriminals & Ransomware Affiliates");
  if (industries.size === 0) industries.add("All Verticals / General Sector Exploitation");
  if (countries.size === 0) countries.add("Global Scope / Non-Geographical Target Vector");

  let chainingType = "other";
  let exploitChainNote = "This vulnerability exposes systems to generic threat vectors. Active patching reduces corporate exposure.";

  const entryTerms = ["bypass", "authentication bypass", "cross-site", "directory traversal", "file upload", "sql injection", "csrf", "ssrf"];
  if (entryTerms.some(term => summaryLower.includes(term))) {
    chainingType = "initial_access";
    exploitChainNote = "Acts as an initial gateway. By bypassing entry bounds, an attacker can access interior services and pivot locally.";
  }

  const execTerms = ["remote code execution", "rce", "arbitrary code execution", "remote command", "deserialization", "buffer overflow", "command injection"];
  if (execTerms.some(term => summaryLower.includes(term))) {
    chainingType = "execution";
    exploitChainNote = "Delivers high-critical command execution capability. Attackers chain this downstream with initial entry points or phishing to establish active persistence.";
  }

  const privTerms = ["privilege", "privilege escalation", "local privilege", "escalation of privilege"];
  if (privTerms.some(term => summaryLower.includes(term))) {
    chainingType = "privilege_escalation";
    exploitChainNote = "Allows low-privileged local nodes to gain administrator or system authority. Extremely lethal once an entry path is established.";
  }

  return {
    threatActors: Array.from(actors),
    industriesTargeted: Array.from(industries),
    countriesTargeted: Array.from(countries),
    chainingType,
    exploitChainNote
  };
}

function colorsMatch(words: string[], text: string) {
  return words.some(w => text.includes(w));
}

// Generate premium Threat Intel using Gemini Model (gemini-3.5-flash) with structured schema
async function queryGeminiThreatIntel(cveId: string, summary: string, cvss: number, cwe: string) {
  const client = getAiClient();
  if (!client) {
    // If no API client, run locally-constructed heuristic scanner
    return guessThreatIntelHeuristics(cveId, summary);
  }

  try {
    const prompt = `You are an elite cyber threat intelligence analyst. Provide structural, high-fidelity threat vector feeds for CVE ID: ${cveId}.
Vulnerability Details:
- Summary: ${summary}
- CVSS base score: ${cvss}
- CWE categorization: ${cwe}

Perform deep threat intelligence correlation. Your response MUST detail:
1. Threat Actors: List of specific state-sponsored APTs, cybercriminal groups, or ransomware syndicates (e.g., Lazarus Group, LockBit, Velvet Chollima) known or suspected to utilize this vector. If none, detail likely exploit actors for this vulnerability pattern.
2. Industries Targeted: List of specific industry verticals they exploit with this (e.g. Critical Infrastructure, Finance, Healthcare, Government, Defense).
3. Countries Targeted: Key geographical regions impacted.
4. Chaining Type: Categorize this CVE's placement as either 'initial_access', 'auth_bypass', 'execution' (such as RCE), 'privilege_escalation', or 'other'.
5. Exploit Chain Note: A highly technical 2-sentence explanation of how this vulnerability is daisy-chained with other vulnerabilities (e.g., combining an initial Auth Bypass with a local Privilege Escalation bug to gain deep domain compromise).`;

    const response = await client.models.generateContent({
      model: "gemini-3.5-flash",
      contents: prompt,
      config: {
        systemInstruction: "You are a Cyber Threat Intelligence (CTI) API server. Return only structured, accurate intelligence details. Use precise, professional security terminology.",
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            threatActors: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: "APTs or cybercriminal groups leveraging this vulnerability. Be specific."
            },
            industriesTargeted: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: "Target sectors."
            },
            countriesTargeted: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: "Key countries targeted."
            },
            chainingType: {
              type: Type.STRING,
              description: "Strictly choose one from: 'initial_access', 'auth_bypass', 'execution', 'privilege_escalation', 'other'"
            },
            exploitChainNote: {
              type: Type.STRING,
              description: "Technical note explaining how attackers chain this exploit with other vulnerabilities."
            }
          },
          required: ["threatActors", "industriesTargeted", "countriesTargeted", "chainingType", "exploitChainNote"]
        }
      }
    });

    const text = response.text;
    if (text) {
      return JSON.parse(text);
    }
  } catch (err) {
    console.warn(`Gemini dynamic lookup failed for ${cveId}, returning local heuristic profile:`, err);
  }

  // Fallback if Gemini fails or times out
  return guessThreatIntelHeuristics(cveId, summary);
}

// Deep Chain Calculator heuristic for multiple entries
function identifyDaisyChains(results: any[]) {
  const chains: Array<{
    entryCve: string;
    entryType: string;
    execCve: string;
    execType: string;
    narrative: string;
  }> = [];

  const entryPoints = results.filter(
    r => r.intel?.chainingType === "initial_access" || r.intel?.chainingType === "auth_bypass"
  );
  
  const executionPoints = results.filter(
    r => r.intel?.chainingType === "execution" || r.intel?.chainingType === "privilege_escalation"
  );

  for (const entry of entryPoints) {
    for (const exec of executionPoints) {
      if (entry.id !== exec.id) {
        chains.push({
          entryCve: entry.id,
          entryType: entry.intel.chainingType,
          execCve: exec.id,
          execType: exec.intel.chainingType,
          narrative: `Attack Path: Threat actors can exploit ${entry.id} (${entry.intel.chainingType}) to gain external foothold or unauthorized credential access, then immediately pivot internally to leverage ${exec.id} (${exec.intel.chainingType}) to command internal system services and seize full domain controls.`
        });
      }
    }
  }

  return chains;
}

// Aggregated Priority assessment score
function calculateCombinedAssessment(results: any[], chainsCount: number) {
  if (results.length === 0) {
    return { priority: "LOW", score: 0, reason: "No active targets submitted for intelligence analysis." };
  }

  const maxCvss = Math.max(...results.map(r => r.details?.cvss || 0.0));
  const hasKev = results.some(r => r.kev !== null);
  const hasRansomware = results.some(r => r.kev?.knownRansomwareCampaignUse === true);
  
  let maxEpss = 0.0;
  for (const r of results) {
    if (r.epss?.epss > maxEpss) {
      maxEpss = r.epss.epss;
    }
  }

  let finalPriority = "LOW";
  let reason = "Submitted vulnerabilities exhibit nominal risk factors with low active exploit potential.";
  let score = 20;

  if (hasRansomware || chainsCount > 0 || (hasKev && maxCvss >= 9.0)) {
    finalPriority = "CRITICAL";
    score = 95;
    if (hasRansomware) {
      reason = "🚨 Alarm level high: Telemetry confirms at least one submitted vulnerability is actively leveraged inside live Ransomware infrastructure.";
    } else if (chainsCount > 0) {
      reason = "⚠️ Attack Sequence Detected: System identified logical pairing conditions enabling external attackers to perform direct entry-to-execution daisy chaining.";
    } else {
      reason = "Overlapping alerts: Selected exploits overlap high CVSS metrics with verified inclusion in CISA's KEV registry.";
    }
  } else if (hasKev || maxCvss >= 8.0 || maxEpss >= 0.20) {
    finalPriority = "HIGH";
    score = 75;
    if (hasKev) {
      reason = "In the wild actions: Active vulnerabilities listed in the CISA Known Exploited Vulnerabilities catalog have high probability of exploitation.";
    } else if (maxEpss >= 0.20) {
      reason = `Threat models report high actual vulnerability breakout probability (EPSS probability: ${(maxEpss * 100).toFixed(1)}%).`;
    } else {
      reason = `Critical Metrics: At least one vulnerability presents standard CVSS metrics in the High threshold scope (${maxCvss}).`;
    }
  } else if (maxCvss >= 5.0 || maxEpss >= 0.05) {
    finalPriority = "MEDIUM";
    score = 50;
    reason = "Standard Threat vectors: Moderate CVSS or EPSS markers suggest actionable patch prioritization during regular maintenance intervals.";
  }

  return { priority: finalPriority, score, reason };
}

// MAIN ANALYSIS API ENDPOINT
app.post("/api/analyze", async (req, res) => {
  try {
    const { cves } = req.body;
    if (!cves || !Array.isArray(cves)) {
      return res.status(400).json({ error: "Missing robust string list of target 'cves'." });
    }

    // Limit to 5 CVEs to prevent excessive rate limits or loading times
    const targetCves = Array.from(new Set(
      cves
        .map((c: string) => c.toUpperCase().trim())
        .filter((c: string) => /^CVE-\d{4}-\d{4,9}$/i.test(c))
    )).slice(0, 5);

    if (targetCves.length === 0) {
      return res.status(400).json({ error: "Invalid input. No formatted CVE IDs matched regex pattern. Format: CVE-YYYY-NNNN" });
    }

    const results = [];

    for (const cveId of targetCves) {
      console.log(`Analyzing target: ${cveId}`);
      // Fetch details from APIs in parallel streams
      const [details, epss] = await Promise.all([
        fetchCveDetails(cveId),
        fetchEpssScore(cveId)
      ]);

      // Check loaded KEV Database cache
      const kev = cisaKevDatabase[cveId] || null;

      // Query Gemini AI Core for Deep Threat Intelligence lookup
      const intel = await queryGeminiThreatIntel(
        cveId,
        details.summary,
        details.cvss,
        details.cwe
      );

      results.push({
        id: cveId,
        details,
        epss,
        kev,
        intel
      });
    }

    const chains = identifyDaisyChains(results);
    const summaryAssessment = calculateCombinedAssessment(results, chains.length);

    return res.json({
      results,
      chains,
      assessment: summaryAssessment,
      cisaMeta: {
        loaded: cisaDatabaseLoaded,
        loadedCount: Object.keys(cisaKevDatabase).length,
        error: cisaDatabaseError
      }
    });

  } catch (error: any) {
    console.error("Critical Analysis Failure:", error);
    return res.status(500).json({ error: "Intelligence analysis failed internally.", details: error.message });
  }
});

// START THE BACKGROUND DOWNLOAD
loadCisaKevCatalog();

// VITE MIDDLEWARE INTERACTION RULES
async function setupExpressServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req: express.Request, res: express.Response) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server starting securely on http://0.0.0.0:${PORT}`);
  });
}

setupExpressServer();
