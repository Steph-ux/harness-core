/**
 * Catalog of installable security tools with their install commands.
 *
 * The ensure function checks whether a tool is present and installs it when
 * it is not. Install commands are non-destructive (they add, never remove)
 * and run with a timeout. The catalog is intentionally static: a dynamic
 * registry that fetches install instructions from the network is a supply
 * chain risk.
 */
import { spawnSync } from "node:child_process";

export type InstallMethod =
  | "apt"
  | "pipx"
  | "pip"
  | "go"
  | "npm"
  | "cargo"
  | "script";

export interface InstallEntry {
  name: string;
  method: InstallMethod;
  package: string;
  description: string;
  /** Extra env vars for the install command. */
  env?: Record<string, string>;
}

const CATALOG: InstallEntry[] = [
  // --- ProjectDiscovery (Go) ---
  { name: "subfinder", method: "go", package: "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", description: "Passive subdomain discovery" },
  { name: "dnsx", method: "go", package: "github.com/projectdiscovery/dnsx/cmd/dnsx@latest", description: "DNS toolkit for bulk resolution" },
  { name: "httpx", method: "go", package: "github.com/projectdiscovery/httpx/cmd/httpx@latest", description: "HTTP probing and tech fingerprinting" },
  { name: "nuclei", method: "go", package: "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", description: "Template-driven vulnerability scanner" },
  { name: "katana", method: "go", package: "github.com/projectdiscovery/katana/cmd/katana@latest", description: "Web crawler for endpoints and JS" },
  { name: "naabu", method: "go", package: "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", description: "Fast port scanner" },
  { name: "tlsx", method: "go", package: "github.com/projectdiscovery/tlsx/cmd/tlsx@latest", description: "TLS certificate inspection" },

  // --- Go tools ---
  { name: "ffuf", method: "go", package: "github.com/ffuf/ffuf/v2@latest", description: "Fast web fuzzer" },
  { name: "gobuster", method: "go", package: "github.com/OJ/gobuster/v3@latest", description: "Directory and DNS brute force" },
  { name: "hakrawler", method: "go", package: "github.com/hakluke/hakrawler@latest", description: "Web crawler for endpoints" },
  { name: "gau", method: "go", package: "github.com/lc/gau/v2/cmd/gau@latest", description: "Fetch known URLs from archives" },
  { name: "cariddi", method: "go", package: "github.com/edoardottt/cariddi/cmd/cariddi@latest", description: "Crawl for endpoints, secrets and strings" },
  { name: "dalfox", method: "go", package: "github.com/hahwul/dalfox/v2@latest", description: "XSS scanner" },
  { name: "gitleaks", method: "go", package: "github.com/gitleaks/gitleaks/v8@latest", description: "Secret detection in git history" },

  // --- Python (pipx) ---
  { name: "bbot", method: "pipx", package: "bbot", description: "Attack surface mapping" },
  { name: "arjun", method: "pipx", package: "arjun", description: "HTTP parameter discovery" },
  { name: "dirsearch", method: "pipx", package: "dirsearch", description: "Web path brute force" },
  { name: "paramspider", method: "pipx", package: "paramspider", description: "Mine parameter names from archived URLs" },
  { name: "waymore", method: "pipx", package: "waymore", description: "Collect URLs from archives" },
  { name: "sqlmap", method: "pipx", package: "sqlmap", description: "SQL injection detection and exploitation" },
  { name: "trufflehog", method: "pipx", package: "trufflehog", description: "Secret detection across repos and files" },
  { name: "semgrep", method: "pipx", package: "semgrep", description: "Static analysis for code and config" },
  { name: "prowler", method: "pipx", package: "prowler", description: "Cloud security posture assessment" },
  { name: "pacu", method: "pipx", package: "pacu", description: "AWS exploitation framework" },
  { name: "impacket", method: "pipx", package: "impacket", description: "Network protocol toolkit for Windows services" },

  // --- APT (Kali/Debian) ---
  { name: "nmap", method: "apt", package: "nmap", description: "Port, service and NSE script scanning" },
  { name: "masscan", method: "apt", package: "masscan", description: "High-speed port scanning" },
  { name: "feroxbuster", method: "apt", package: "feroxbuster", description: "Recursive content discovery" },
  { name: "nikto", method: "apt", package: "nikto", description: "Web server misconfiguration scanner" },
  { name: "hydra", method: "apt", package: "hydra", description: "Online credential testing" },
  { name: "john", method: "apt", package: "john", description: "Password hash cracking" },
  { name: "hashcat", method: "apt", package: "hashcat", description: "Password hash cracking (GPU)" },
  { name: "responder", method: "apt", package: "responder", description: "LLMNR/NBT-NS/mDNS poisoner" },
  { name: "netexec", method: "apt", package: "netexec", description: "Network service exploitation (SMB, LDAP, WinRM)" },
  { name: "bloodhound", method: "apt", package: "bloodhound", description: "AD relationship mapping" },
  { name: "wpscan", method: "apt", package: "wpscan", description: "WordPress vulnerability scanning" },
  { name: "exiftool", method: "apt", package: "libimage-exiftool-perl", description: "File metadata extraction" },
  { name: "binwalk", method: "apt", package: "binwalk", description: "Firmware analysis" },
  { name: "steghide", method: "apt", package: "steghide", description: "Steganography" },
  { name: "foremost", method: "apt", package: "foremost", description: "File carving" },
  { name: "amass", method: "apt", package: "amass", description: "Attack surface mapping" },
  { name: "whatweb", method: "apt", package: "whatweb", description: "Web technology fingerprinting" },
  { name: "wafw00f", method: "apt", package: "wafw00f", description: "WAF detection" },

  // --- Cloud CLIs ---
  { name: "aws", method: "pip", package: "awscli", description: "AWS command-line interface" },
  { name: "az", method: "pip", package: "azure-cli", description: "Azure command-line interface" },
  { name: "kubectl", method: "apt", package: "kubectl", description: "Kubernetes CLI" },
  { name: "trivy", method: "apt", package: "trivy", description: "Container and dependency vulnerability scanning" },

  // --- NPM ---
  { name: "retire", method: "npm", package: "retire", description: "JS dependency vulnerability scanner" },

  // --- Cargo ---
  { name: "rustscan", method: "cargo", package: "rustscan", description: "Fast port discovery with nmap handoff" },
];

const INDEX = new Map(CATALOG.map((e) => [e.name, e]));

export function lookupInstall(name: string): InstallEntry | undefined {
  return INDEX.get(name);
}

export function listInstallable(): InstallEntry[] {
  return [...CATALOG];
}

function which(name: string): boolean {
  const cmd = process.platform === "win32" ? "where.exe" : "which";
  const result = spawnSync(cmd, [name], {
    timeout: 5000,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  return result.status === 0;
}

function installCommand(entry: InstallEntry): { cmd: string; args: string[] } {
  switch (entry.method) {
    case "apt":
      return { cmd: "sudo", args: ["apt-get", "install", "-y", entry.package] };
    case "pipx":
      return { cmd: "pipx", args: ["install", entry.package] };
    case "pip":
      return { cmd: "pip", args: ["install", "--user", entry.package] };
    case "go":
      return { cmd: "go", args: ["install", entry.package] };
    case "npm":
      return { cmd: "npm", args: ["install", "-g", entry.package] };
    case "cargo":
      return { cmd: "cargo", args: ["install", entry.package] };
    case "script":
      return { cmd: "bash", args: ["-c", entry.package] };
  }
}

export interface EnsureResult {
  name: string;
  wasPresent: boolean;
  installed: boolean;
  method?: InstallMethod;
  error?: string;
}

export function ensure(name: string, timeout = 300_000): EnsureResult {
  if (which(name)) return { name, wasPresent: true, installed: true };
  const entry = INDEX.get(name);
  if (!entry) return { name, wasPresent: false, installed: false, error: "Unknown tool — not in installable catalog" };
  const { cmd, args } = installCommand(entry);
  const prereqOk = which(cmd === "sudo" ? "apt-get" : cmd);
  if (!prereqOk)
    return { name, wasPresent: false, installed: false, method: entry.method,
      error: `Install method "${entry.method}" unavailable: ${cmd} not found` };
  const result = spawnSync(cmd, args, {
    timeout,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, ...(entry.env ?? {}) },
  });
  if (result.error || result.status !== 0) {
    const stderr = String(result.stderr ?? result.error?.message ?? "").slice(0, 500);
    return { name, wasPresent: false, installed: false, method: entry.method,
      error: `Install failed (exit ${result.status}): ${stderr}` };
  }
  const present = which(name);
  return { name, wasPresent: false, installed: present, method: entry.method,
    ...(present ? {} : { error: "Install command succeeded but binary not found in PATH" }) };
}

export function ensureMany(names: string[], timeout = 300_000): EnsureResult[] {
  return names.map((n) => ensure(n, timeout));
}
