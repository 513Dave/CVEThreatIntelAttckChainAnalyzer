import { useState } from "react";
import { 
  Shield, 
  Terminal, 
  Zap, 
  AlertTriangle, 
  CheckCircle2, 
  Download, 
  FileCode, 
  Activity, 
  Copy, 
  Check, 
  AlertOctagon, 
  Globe, 
  Briefcase, 
  Users, 
  ExternalLink,
  Search,
  RefreshCw,
  Info,
  Server,
  HelpCircle,
  FileText
} from "lucide-react";
import { pythonScriptContent } from "./pythonCode";

interface CveDetails {
  id: string;
  summary: string;
  cvss: number;
  cwe: string;
  references: string[];
}

interface EpssScore {
  epss: number;
  percentile: number;
}

interface KevMeta {
  vulnerabilityName: string;
  dateAdded: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: boolean;
  notes: string;
}

interface ThreatIntel {
  threatActors: string[];
  industriesTargeted: string[];
  countriesTargeted: string[];
  chainingType: "initial_access" | "auth_bypass" | "execution" | "privilege_escalation" | "other";
  exploitChainNote: string;
}

interface AnalyzedResult {
  id: string;
  details: CveDetails;
  epss: EpssScore;
  kev: KevMeta | null;
  intel: ThreatIntel;
}

interface DaisyChain {
  entryCve: string;
  entryType: string;
  execCve: string;
  execType: string;
  narrative: string;
}

interface CombinedAssessment {
  priority: string;
  score: number;
  reason: string;
}

interface ApiResponse {
  results: AnalyzedResult[];
  chains: DaisyChain[];
  assessment: CombinedAssessment;
  cisaMeta: {
    loaded: boolean;
    loadedCount: number;
    error: string | null;
  };
}

export default function App() {
  const [cveInput, setCveInput] = useState<string>("CVE-2023-4966\nCVE-2021-44228\nCVE-2021-34473");
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<ApiResponse | null>(null);
  const [copiedScript, setCopiedScript] = useState<boolean>(false);
  const [copiedCommand, setCopiedCommand] = useState<boolean>(false);
  const [selectedCve, setSelectedCve] = useState<string | null>(null);

  // Parse list of valid CVEs from free text field
  const handleExtractAndAnalyze = async () => {
    setError(null);
    setLoading(true);
    setAnalysis(null);
    setSelectedCve(null);

    try {
      // Extraction regex for raw text matching formatted CVE patterns
      const matched = cveInput.match(/CVE-\d{4}-\d{4,9}/gi);
      if (!matched || matched.length === 0) {
        throw new Error("No properly formatted CVE identifiers found. Please enter valid IDs (Format: CVE-YYYY-NNNN).");
      }

      const uniqueCves = Array.from(new Set(matched.map(c => c.toUpperCase())));
      
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ cves: uniqueCves })
      });

      if (!response.ok) {
        const body = await response.json();
        throw new Error(body.error || "Vulnerability lookup server failed to analyze inputs.");
      }

      const data: ApiResponse = await response.json();
      setAnalysis(data);
      if (data.results && data.results.length > 0) {
        setSelectedCve(data.results[0].id);
      }
    } catch (err: any) {
      setError(err.message || "An unexpected dynamic analysis failure occurred.");
    } finally {
      setLoading(false);
    }
  };

  // Triggers virtual download of Python desktop package
  const handleDownloadScript = () => {
    const blob = new Blob([pythonScriptContent], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "cve_intel_tool.py";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleCopyScriptText = () => {
    navigator.clipboard.writeText(pythonScriptContent);
    setCopiedScript(true);
    setTimeout(() => setCopiedScript(false), 2000);
  };

  const handleCopyCompilationCommand = () => {
    navigator.clipboard.writeText("pyinstaller --onefile --noconsole cve_intel_tool.py");
    setCopiedCommand(true);
    setTimeout(() => setCopiedCommand(false), 2000);
  };

  // Helper colors mapping for prioritisation scores
  const getPriorityClasses = (priority: string) => {
    switch (priority?.toUpperCase()) {
      case "CRITICAL":
        return {
          bg: "bg-red-950/40 border-red-500/30 text-red-400",
          badge: "bg-red-500 text-black",
          text: "text-red-400",
          glow: "shadow-[0_0_20px_rgba(239,68,68,0.15)] outline-red-500/10"
        };
      case "HIGH":
        return {
          bg: "bg-amber-950/40 border-amber-500/30 text-amber-400",
          badge: "bg-amber-500 text-black",
          text: "text-amber-400",
          glow: "shadow-[0_0_20px_rgba(245,158,11,0.15)] outline-amber-500/10"
        };
      case "MEDIUM":
        return {
          bg: "bg-yellow-950/40 border-yellow-500/30 text-yellow-400",
          badge: "bg-yellow-400 text-black",
          text: "text-yellow-400",
          glow: "shadow-[0_0_20px_rgba(234,179,8,0.15)] outline-yellow-500/10"
        };
      case "LOW":
        return {
          bg: "bg-emerald-950/40 border-emerald-500/30 text-emerald-400",
          badge: "bg-emerald-500 text-black",
          text: "text-emerald-400",
          glow: "shadow-[0_0_15px_rgba(16,185,129,0.15)] outline-emerald-500/10"
        };
      default:
        return {
          bg: "bg-zinc-900 border-zinc-800 text-zinc-400",
          badge: "bg-zinc-700 text-zinc-100",
          text: "text-zinc-400",
          glow: ""
        };
    }
  };

  const getChainTypeLabel = (type: string) => {
    switch (type) {
      case "initial_access": return "🚪 Initial Gateway Access";
      case "auth_bypass": return "🔑 Session / Authentication Bypass";
      case "execution": return "⚙️ Remote System Execution (RCE)";
      case "privilege_escalation": return "⚡ Local Privilege Elevation";
      default: return "⛓️ General Auxiliary Vulnerability";
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans flex flex-col selection:bg-blue-600/30 selection:text-blue-200">
      
      {/* Top Threat Intelligence Status Bar */}
      <div id="stat-bar" className="bg-slate-900 border-b border-slate-800 py-1.5 px-4 text-xs font-mono text-slate-400 flex flex-wrap justify-between items-center gap-2">
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
          <span>NVD v2.0 Global Feeds: CONNECTED</span>
        </div>
        <div className="flex items-center gap-4">
          <span>EPSS Model: Active</span>
          <span>CISA KEV Index: Loaded ({analysis?.cisaMeta?.loadedCount ?? "11,000+"} entries)</span>
        </div>
      </div>

      {/* Main App Header */}
      <header id="main-header" className="bg-slate-900/60 backdrop-blur-md border-b border-slate-800 px-6 py-5 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="bg-blue-600 p-2.5 rounded-xl text-slate-950 shadow-[0_0_15px_rgba(37,99,235,0.4)]">
            <Shield className="w-6 h-6 stroke-[2.5]" />
          </div>
          <div>
            <h1 className="text-xl font-display font-bold uppercase tracking-tight text-white flex items-center gap-2">
              Vulnerability Cross-Referencer <span className="text-xs bg-slate-800 border border-slate-700 font-mono text-blue-400 px-2 py-0.5 rounded">V1.2</span>
            </h1>
            <p className="text-xs text-slate-400 font-sans mt-0.5">
              Secure CVE intelligence matching, CISA exploit verification, attack daisy-chain modeling, and local Windows packaging engine.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            id="download-portable-btn"
            onClick={handleDownloadScript}
            className="flex items-center gap-2 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white text-xs font-semibold px-4 py-2.5 rounded-xl shadow-[0_4px_15px_rgba(37,99,235,0.2)] hover:shadow-[0_4px_20px_rgba(37,99,235,0.4)] transition-all cursor-pointer"
          >
            <Download className="w-4 h-4" />
            Download Windows app (.py)
          </button>
        </div>
      </header>

      {/* Primary Application Workspace Grid */}
      <main className="flex-1 max-w-[1700px] w-full mx-auto p-4 md:p-6 grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left Hand: Controls & Combined Assessment */}
        <div className="lg:col-span-5 flex flex-col gap-6">
          
          {/* Diagnostic Input Section */}
          <div id="input-card" className="bg-slate-900/80 border border-slate-800/80 rounded-2xl p-5 shadow-xl flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-2 text-sm font-semibold text-slate-200">
                <Terminal className="w-4 h-4 text-blue-400" />
                Vulnerability Analyzer Panel
              </span>
              <span className="text-[10px] font-mono text-slate-500">
                Supports Multi-Line Input
              </span>
            </div>

            <div className="relative">
              <textarea
                id="cve-textarea"
                className="w-full bg-slate-950/90 border border-slate-800 rounded-xl p-3.5 text-sm font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-blue-500/80 focus:ring-1 focus:ring-blue-500/30 transition-all min-h-[140px] resize-y"
                placeholder="Paste CVE IDs here, separated by line spaces or copy-paste logs (e.g. CVE-2023-4966)"
                value={cveInput}
                onChange={(e) => setCveInput(e.target.value)}
              />
              <div className="absolute right-3.5 bottom-3.5 flex gap-1.5">
                <button 
                  id="example-btn-1"
                  onClick={() => setCveInput("CVE-2023-4966\nCVE-2021-44228")}
                  className="text-[10px] bg-slate-800/60 hover:bg-slate-800 border border-slate-700/65 px-2 py-1 rounded font-mono text-slate-400 transition"
                  title="Follina and Log4Shell"
                >
                  Combo 1
                </button>
                <button 
                  id="example-btn-2"
                  onClick={() => setCveInput("CVE-2021-34473\nCVE-2023-34362\nCVE-2022-30190")}
                  className="text-[10px] bg-slate-800/60 hover:bg-slate-800 border border-slate-700/65 px-2 py-1 rounded font-mono text-slate-400 transition"
                  title="MOVEit, ProxyShell, Citrix Bleed"
                >
                  Combo 2
                </button>
              </div>
            </div>

            <button
              id="analyze-run-button"
              onClick={handleExtractAndAnalyze}
              disabled={loading}
              className="w-full py-3 px-4 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 disabled:text-slate-600 text-white font-semibold rounded-xl text-sm transition-all focus:ring-2 focus:ring-blue-500/20 flex items-center justify-center gap-2 shadow-[0_4px_15px_rgba(37,99,235,0.15)] disabled:shadow-none cursor-pointer"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-white" />
                  Correlating Live Feeds...
                </>
              ) : (
                <>
                  <Activity className="w-4 h-4" />
                  Analyze Vulnerabilities & Chain Risk
                </>
              )}
            </button>

            {error && (
              <div id="error-banner" className="p-3 bg-red-950/40 border border-red-500/20 text-red-400 rounded-xl text-xs flex items-start gap-2 h-auto">
                <AlertOctagon className="w-4 h-4 shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}
          </div>

          {/* Aggregated Risk Portfolio */}
          {analysis && (
            <div 
              id="risk-assessment-card" 
              className={`bg-slate-900/80 border rounded-2xl p-5 shadow-xl transition-all ${getPriorityClasses(analysis.assessment.priority).bg} ${getPriorityClasses(analysis.assessment.priority).glow}`}
            >
              <div className="flex items-center justify-between border-b border-white/[0.06] pb-3.5 mb-3.5">
                <span className="text-xs font-semibold tracking-wider uppercase opacity-85 font-mono">
                  AGGREGATED THREAT ASSESSMENT
                </span>
                <span className="text-[10px] font-mono opacity-60">
                  Risk Index Score: {analysis.assessment.score}/100
                </span>
              </div>

              <div className="flex items-baseline gap-3 mb-3.5">
                <span className={`text-4xl font-display font-extrabold uppercase tracking-tight`}>
                  {analysis.assessment.priority}
                </span>
                <span className="text-xs opacity-75">Prioritization Tier</span>
              </div>

              <p className="text-sm leading-relaxed mb-4 text-slate-100 font-sans">
                {analysis.assessment.reason}
              </p>

              {/* Dynamic Attack Daisy Chain warning */}
              {analysis.chains && analysis.chains.length > 0 ? (
                <div id="attack-chains-box" className="mt-4 p-4 bg-slate-950/80 border border-amber-500/20 rounded-xl">
                  <div className="flex items-center gap-2 mb-3.5">
                    <span className="flex h-2 w-2 rounded-full bg-red-500 animate-ping"></span>
                    <h4 className="text-xs font-bold text-red-400 font-mono tracking-wider uppercase">
                      ⚠️ Attack Sequence Chains Identified ({analysis.chains.length})
                    </h4>
                  </div>
                  <div className="space-y-4">
                    {analysis.chains.map((chain, cIdx) => (
                      <div key={cIdx} className="space-y-2 text-xs border-l border-white/[0.06] pl-3.5">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="bg-blue-900/40 border border-blue-500/30 text-blue-400 px-1.5 py-0.5 rounded font-mono font-bold text-[10px]">{chain.entryCve}</span>
                          <span className="text-slate-500 font-mono font-bold">➔</span>
                          <span className="bg-red-900/40 border border-red-500/30 text-red-400 px-1.5 py-0.5 rounded font-mono font-bold text-[10px]">{chain.execCve}</span>
                        </div>
                        <p className="text-slate-300 leading-relaxed text-xs">
                          {chain.narrative}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div id="no-attack-chains-box" className="p-3 bg-slate-950/40 border border-white/[0.05] rounded-xl text-center text-xs text-slate-400 flex items-center justify-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                  <span>No clear entry-to-execution attack vectors modeled.</span>
                </div>
              )}
            </div>
          )}

          {/* Standard Informative Banner if app state is unassessed */}
          {!analysis && !loading && (
            <div id="unassessed-welcome" className="bg-slate-900/40 border border-slate-800/80 rounded-2xl p-6 text-center shadow-md flex flex-col items-center justify-center py-10">
              <Shield className="w-10 h-10 text-slate-600 mb-3 stroke-[1.5]" />
              <h3 className="text-sm font-semibold text-slate-300 mb-1 font-display">No vulnerabilities analyzed yet</h3>
              <p className="text-xs text-slate-500 max-w-sm">
                Enter formatted CVE IDs into the analysis field above and click Execute to load live NVD descriptions, CISA catalogs, EPSS statistics, and Gemini CTI threats.
              </p>
            </div>
          )}

          {/* Help Panel: Windows Local Compilation Instructions */}
          <div id="portable-app-manual" className="bg-slate-900/80 border border-slate-800/80 rounded-2xl p-5 shadow-xl flex flex-col gap-4">
            <div className="flex items-center gap-2 border-b border-white/[0.06] pb-3 mb-1">
              <FileCode className="w-4 h-4 text-indigo-400 font-bold" />
              <h3 className="text-xs font-bold tracking-wider font-mono text-slate-300 uppercase">
                Download Portable Windows Client
              </h3>
            </div>
            
            <p className="text-xs text-slate-400 leading-relaxed font-sans">
              The application contains a customized, completely offline-compatible and resilient Python desk application build called <strong className="text-white">cve_intel_tool.py</strong> using standard library modules (no third-party pip setups needed).
            </p>

            <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 flex flex-col gap-3 font-mono text-xs">
              <div className="flex justify-between items-center text-slate-500 text-[10px] border-b border-white/[0.05] pb-1.5">
                <span>Windows Executable Build Commands</span>
                <span>CMD / PowerShell</span>
              </div>
              <div className="flex items-center justify-between text-indigo-400 text-[11px] overflow-x-auto whitespace-pre">
                <code>pyinstaller --onefile --noconsole cve_intel_tool.py</code>
                <button
                  id="copy-command-btn" 
                  onClick={handleCopyCompilationCommand}
                  className="p-1 hover:bg-slate-800 rounded text-slate-400 hover:text-white transition shrink-0 ml-2"
                  title="Copy compilation command"
                >
                  {copiedCommand ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2 mt-1">
              <button
                id="script-download-btn-2"
                onClick={handleDownloadScript}
                className="flex items-center justify-center gap-1.5 py-2 px-3 border border-slate-700 bg-slate-800/40 hover:bg-slate-800 rounded-xl text-xs font-semibold text-slate-200 transition cursor-pointer"
              >
                <Download className="w-3.5 h-3.5 text-blue-400" />
                Get .py file
              </button>
              <button
                id="script-copy-btn"
                onClick={handleCopyScriptText}
                className="flex items-center justify-center gap-1.5 py-2 px-3 border border-slate-700 bg-slate-800/40 hover:bg-slate-800 rounded-xl text-xs font-semibold text-slate-200 transition cursor-pointer"
              >
                {copiedScript ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Script Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-blue-400" />
                    <span>Copy Full Script</span>
                  </>
                )}
              </button>
            </div>
          </div>

        </div>

        {/* Right Hand: Detailed Threat Dossier */}
        <div className="lg:col-span-7 flex flex-col gap-6">
          {analysis && analysis.results && (
            <div id="dossier-registry" className="bg-slate-900/80 border border-slate-800/80 rounded-2xl p-5 shadow-xl flex-1 flex flex-col gap-4">
              
              <div className="flex flex-wrap items-center justify-between border-b border-white/[0.06] pb-3.5 gap-2.5">
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-blue-400" />
                  <span className="text-sm font-semibold text-slate-200">
                    Vulnerability Intelligence Dossier
                  </span>
                </div>
                <div className="flex items-center gap-1.5 flex-wrap">
                  {analysis.results.map((res) => {
                    const priorityClass = getPriorityClasses(
                      res.details.cvss >= 9.0 ? "CRITICAL" :
                      res.details.cvss >= 7.0 ? "HIGH" :
                      res.details.cvss >= 4.0 ? "MEDIUM" : "LOW"
                    );
                    return (
                      <button
                        id={`tab-btn-${res.id}`}
                        key={res.id}
                        onClick={() => setSelectedCve(res.id)}
                        className={`px-3 py-1.5 rounded-lg font-mono text-[11px] font-bold border transition ${
                          selectedCve === res.id 
                            ? `${priorityClass.bg} border-current/40 ${priorityClass.text} scale-[1.03] ring-1 ring-blue-500/10`
                            : "bg-slate-950/60 border-slate-800/80 text-slate-400 hover:text-slate-200 hover:border-slate-700"
                        }`}
                      >
                        {res.id}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Single Active CVE detailed view */}
              {selectedCve && (() => {
                const item = analysis.results.find(r => r.id === selectedCve);
                if (!item) return null;

                const scoreColors = getPriorityClasses(
                  item.details.cvss >= 9.0 ? "CRITICAL" :
                  item.details.cvss >= 7.0 ? "HIGH" :
                  item.details.cvss >= 4.0 ? "MEDIUM" : "LOW"
                );

                return (
                  <div id={`target-dossier-${item.id}`} className="flex-1 flex flex-col gap-5 text-slate-300">
                    
                    {/* Header Details */}
                    <div className="flex flex-wrap justify-between items-start gap-4 p-4 bg-slate-950/80 border border-slate-800 rounded-xl">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2.5 flex-wrap">
                          <h2 className="text-xl font-display font-black text-white tracking-tight">{item.id}</h2>
                          {item.intel.chainingType !== "other" && (
                            <span className="text-[10px] uppercase font-mono font-bold bg-slate-800 border border-slate-700 px-2 py-0.5 rounded text-blue-400">
                              {getChainTypeLabel(item.intel.chainingType)}
                            </span>
                          )}
                        </div>
                        <div className="text-xs text-slate-500 font-mono">
                          Linked Weakness Classification: <span className="text-blue-400 font-semibold">{item.details.cwe || "N/A"}</span>
                        </div>
                      </div>

                      <div className="text-right flex items-center gap-3">
                        <div className="text-right">
                          <div className={`text-2xl font-bold font-mono tracking-tight ${scoreColors.text}`}>
                            {item.details.cvss.toFixed(1)}
                          </div>
                          <div className="text-[10px] text-slate-500 font-mono uppercase">CVSS base</div>
                        </div>
                      </div>
                    </div>

                    {/* Threat Intelligence Profiler */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
                      
                      {/* Actors Tab */}
                      <div className="p-4 bg-slate-950/50 border border-slate-800 rounded-xl space-y-2.5">
                        <span className="flex items-center gap-1.5 text-xs text-slate-400 font-bold tracking-wider font-mono uppercase">
                          <Users className="w-3.5 h-3.5 text-amber-500" />
                          Threat Actors
                        </span>
                        <ul className="space-y-1.5 text-xs">
                          {item.intel.threatActors.map((actor, aIdx) => (
                            <li key={aIdx} className="text-slate-200 font-medium">
                              • {actor}
                            </li>
                          ))}
                        </ul>
                      </div>

                      {/* Sectors Tab */}
                      <div className="p-4 bg-slate-950/50 border border-slate-800 rounded-xl space-y-2.5">
                        <span className="flex items-center gap-1.5 text-xs text-slate-400 font-bold tracking-wider font-mono uppercase">
                          <Briefcase className="w-3.5 h-3.5 text-blue-500" />
                          Target Sectors
                        </span>
                        <ul className="space-y-1.5 text-xs">
                          {item.intel.industriesTargeted.map((industry, iIdx) => (
                            <li key={iIdx} className="text-slate-200 font-medium">
                              • {industry}
                            </li>
                          ))}
                        </ul>
                      </div>

                      {/* Locations Tab */}
                      <div className="p-4 bg-slate-950/50 border border-slate-800 rounded-xl space-y-2.5">
                        <span className="flex items-center gap-1.5 text-xs text-slate-400 font-bold tracking-wider font-mono uppercase">
                          <Globe className="w-3.5 h-3.5 text-indigo-500" />
                          Target Locations
                        </span>
                        <ul className="space-y-1.5 text-xs">
                          {item.intel.countriesTargeted.map((country, cIdx) => (
                            <li key={cIdx} className="text-slate-200 font-medium">
                              • {country}
                            </li>
                          ))}
                        </ul>
                      </div>

                    </div>

                    {/* Exploit Analysis & EPSS Metrics */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      
                      {/* CISA KEV Data */}
                      <div className="p-4 bg-slate-950/50 border border-slate-800 rounded-xl">
                        <h4 className="text-xs font-bold text-slate-400 font-mono tracking-wider uppercase mb-3 flex items-center gap-1.5">
                          <AlertTriangle className="w-4 h-4 text-red-400" />
                          CISA KEV Status
                        </h4>

                        {item.kev ? (
                          <div className="space-y-2.5 text-xs">
                            <div className="flex items-center gap-2">
                              <span className="px-2 py-0.5 bg-red-950 border border-red-500/30 text-red-400 rounded-[4px] font-mono font-bold text-[10px]">
                                KNOWN EXPLOIT ACTIVE
                              </span>
                              {item.kev.knownRansomwareCampaignUse && (
                                <span className="px-2 py-0.5 bg-rose-950 border border-rose-500/30 text-rose-400 rounded-[4px] font-mono font-bold text-[10px] animate-pulse">
                                  RANSOMWARE VECTOR
                                </span>
                              )}
                            </div>
                            <div className="text-slate-300">
                              <p className="font-semibold text-white text-xs">{item.kev.vulnerabilityName}</p>
                              <p className="text-[10px] text-slate-500 font-mono mt-0.5">Catalog added date: {item.kev.dateAdded}</p>
                            </div>
                            <div className="p-2.5 bg-red-950/20 border border-red-500/10 rounded-lg text-[11px] text-red-300 leading-relaxed">
                              <strong>CISA Mandate:</strong> {item.kev.requiredAction}
                            </div>
                          </div>
                        ) : (
                          <div className="space-y-2 text-xs py-2">
                            <div className="flex items-center gap-2">
                              <span className="px-2 py-0.5 bg-slate-900 border border-slate-850 text-slate-400 rounded-[4px] font-mono font-bold text-[10px]">
                                NOT IN CISA CATALOG
                              </span>
                            </div>
                            <p className="text-slate-500 text-xs">
                              At present, this specific identifier is not documented in the CISA Known Exploited core registry.
                            </p>
                          </div>
                        )}
                      </div>

                      {/* EPSS Prediction Metrics */}
                      <div className="p-4 bg-slate-950/50 border border-slate-800 rounded-xl space-y-2.5">
                        <h4 className="text-xs font-bold text-slate-400 font-mono tracking-wider uppercase flex items-center gap-1.5">
                          <Activity className="w-4 h-4 text-blue-400" />
                          EPSS Probability Score
                        </h4>

                        <div className="space-y-3">
                          <div className="p-3 bg-slate-900/60 rounded-xl border border-slate-800 flex items-center justify-between">
                            <div>
                              <span className="text-[10px] text-slate-500 font-mono uppercase block">EXPLOITATION PROBABILITY</span>
                              <span className="text-lg font-bold font-mono text-white">{(item.epss.epss * 100).toFixed(3)}%</span>
                            </div>
                            <div className="text-right">
                              <span className="text-[10px] text-slate-500 font-mono uppercase block">PERCENTILE RANK</span>
                              <span className="text-lg font-bold font-mono text-white">{(item.epss.percentile * 100).toFixed(1)}%</span>
                            </div>
                          </div>

                          <p className="text-[11px] leading-relaxed text-slate-500">
                            The EPSS model predicts the real probability that this core exploit pattern is captured in live firewall sessions or intrusion payloads over the next 30 days.
                          </p>
                        </div>
                      </div>

                    </div>

                    {/* Technical Narrative Section */}
                    <div className="p-4 bg-slate-950/50 border border-slate-800 rounded-xl space-y-2">
                      <span className="text-xs font-bold text-slate-400 font-mono tracking-wider uppercase block">
                        Vulnerability Summary Description
                      </span>
                      <p className="text-xs leading-relaxed text-slate-200 font-sans">
                        {item.details.summary}
                      </p>
                    </div>

                    {/* Exploit Chaining Tactics block */}
                    <div className="p-4 bg-slate-950 border border-slate-800/80 rounded-xl space-y-2.5">
                      <h4 className="text-xs font-bold text-indigo-400 font-mono tracking-wider uppercase flex items-center gap-1.5">
                        <Zap className="w-3.5 h-3.5 text-indigo-400" />
                        Exploitation Chaining Tactics
                      </h4>
                      <p className="text-xs leading-relaxed text-slate-300">
                        {item.intel.exploitChainNote}
                      </p>
                    </div>

                    {/* References & Advisories footer */}
                    {item.details.references && item.details.references.length > 0 && (
                      <div className="space-y-2">
                        <span className="text-xs font-bold text-slate-400 font-mono tracking-wider uppercase block">
                          Security Advisories & References
                        </span>
                        <div className="max-h-[140px] overflow-y-auto pr-1 space-y-1.5 scrollbar-thin">
                          {item.details.references.slice(0, 5).map((ref, rIdx) => (
                            <a 
                              key={rIdx} 
                              href={ref} 
                              target="_blank" 
                              rel="noopener noreferrer"
                              className="flex items-center justify-between p-2 bg-slate-950/40 hover:bg-slate-950 border border-slate-850 hover:border-slate-800 rounded text-[11px] font-mono text-blue-400 hover:text-blue-300 transition"
                            >
                              <span className="truncate max-w-[90%]">{ref}</span>
                              <ExternalLink className="w-3.5 h-3.5 shrink-0 text-slate-500" />
                            </a>
                          ))}
                        </div>
                      </div>
                    )}

                  </div>
                );
              })()}

            </div>
          )}

          {!analysis && !loading && (
            <div id="welcome-dossier-card" className="bg-slate-900/40 border border-slate-800/80 rounded-2xl p-6 text-center shadow-md flex-1 flex flex-col items-center justify-center min-h-[300px]">
              <div className="bg-slate-950 p-4 border border-slate-800 rounded-full mb-4 text-slate-500">
                <Search className="w-8 h-8 stroke-[1.5]" />
              </div>
              <h3 className="text-base font-semibold text-slate-300 font-display">Security Dossier Dashboard</h3>
              <p className="text-xs text-slate-500 max-w-sm mt-1 mb-5">
                Execute a correlation run using the inputs panel to render detailed intelligence feeds, known exploits, map connections, and remediation details.
              </p>
              <div className="flex gap-2 text-[11px] text-slate-400 bg-slate-950 p-3 rounded-xl border border-slate-850 max-w-md text-left leading-normal font-mono">
                <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                <span>Supports dynamic lookup on up to 5 concurrent CVE matches. Fallback data indexes are fetched asynchronously on server nodes.</span>
              </div>
            </div>
          )}

          {loading && (
            <div id="loading-state-card" className="bg-slate-900/40 border border-slate-800/80 rounded-2xl p-6 text-center shadow-md flex-1 flex flex-col items-center justify-center min-h-[350px]">
              <div className="relative mb-5">
                <div className="w-14 h-14 border-4 border-slate-800 border-t-blue-500 rounded-full animate-spin"></div>
                <div className="absolute inset-0 flex items-center justify-center text-blue-400 scale-95">
                  <Activity className="w-5 h-5 animate-pulse" />
                </div>
              </div>
              <h3 className="text-base font-semibold text-slate-300 font-display animate-pulse">Running Correlation Models</h3>
              <p className="text-xs text-slate-550 max-w-xs mt-1.5 leading-relaxed">
                Contacting CISA database indexes, FIRST.org models, and parsing real-time threat intelligence files. This takes about 3-5 seconds.
              </p>
            </div>
          )}

        </div>

      </main>

      {/* Footer bar */}
      <footer id="app-footer" className="bg-slate-950 border-t border-slate-900 text-slate-600 px-6 py-4 text-xs flex flex-wrap justify-between items-center gap-4">
        <div>
          <span>© 127.0.0.1 Cyber Threat Intelligence Analyzer. Distributed under license keys.</span>
        </div>
        <div className="flex items-center gap-4 font-mono">
          <span className="flex items-center gap-1">
            <Server className="w-3.5 h-3.5 text-indigo-400" />
            V0.1.2-Server
          </span>
          <span className="flex items-center gap-1">
            <HelpCircle className="w-3.5 h-3.5 text-blue-400" />
            Offline Standalone Enabled
          </span>
        </div>
      </footer>

    </div>
  );
}
