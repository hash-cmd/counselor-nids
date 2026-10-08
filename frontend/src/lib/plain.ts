/** Plain-language names for the system's technical terms, so the dashboard reads
 *  without knowing the research behind it. Unknown names fall back to the original. */

const DETECTORS: Record<string, { name: string; knows: string }> = {
  live_dos: { name: "Flood detector", knows: "flooding attacks that overload a server (DoS)" },
  live_access: { name: "Break-in detector", knows: "password guessing, and some website attacks (the rule checker is the main defence against those: it learned from too few examples)" },
  snort: { name: "Rule checker (Snort)", knows: "known attack patterns inside the traffic; advises the AI detectors when they are unsure" },
  live_bot: { name: "Botnet detector", knows: "infected machines secretly checking in with an attacker's control server (botnet)" },
};

/** Thesis experiment configurations (scripts/live_detectors/adapt.py). */
export const CONFIGS: Record<string, { name: string; ablation?: boolean }> = {
  ai: { name: "Deployed system (AI detectors advising each other)" },
  "+snort": { name: "+ Snort as a counselor" },
  "+rules": { name: "+ Snort counselor, adaptive rule trust" },
  "+learn": { name: "+ Snort counselor, learning from agreement" },
  full: { name: "Proposed: Snort counselor + rule trust + learning" },
  "+trust": { name: "Ablation: + adaptive detector trust", ablation: true },
  "+trust-reselect": { name: "Ablation: + detectors re-select classifiers", ablation: true },
  "full+trust": { name: "Ablation: proposed + adaptive detector trust", ablation: true },
  "snort alone": { name: "Baseline: Snort alone" },
  "ai or snort": { name: "Baseline: AI or Snort" },
};
export const configName = (key: string) => CONFIGS[key]?.name ?? key;

export const detectorName = (name: string) => DETECTORS[name]?.name ?? name;
export const detectorKnows = (name: string) => DETECTORS[name]?.knows ?? null;

/** Dataset labels (e.g. "DoS Hulk", "FTP-Patator") as "Plain name (original)". */
export function attackName(label: string): string {
  const l = label.toLowerCase();
  const plain =
    l === "benign" ? "Normal traffic"
    : /ddos/.test(l) ? "Large-scale flooding"
    : /dos/.test(l) ? "Flooding attack"
    : /portscan|port scan/.test(l) ? "Port scan"
    : /sql/.test(l) ? "Website attack: database break-in"
    : /xss/.test(l) ? "Website attack: script injection"
    : /web/.test(l) ? "Website attack"
    : /ftp|ssh|brute|patator/.test(l) ? "Password guessing"
    : /bot/.test(l) ? "Infected machine (botnet)"
    : /infil/.test(l) ? "Insider intrusion"
    : null;
  return plain && plain !== label ? (l === "benign" ? plain : `${plain} (${label})`) : label;
}

/** A short, plain explanation of what a Snort rule looks for. */
export function ruleName(msg: string): string {
  const m = msg.replace(/^NIDS /, "");
  const l = m.toLowerCase();
  const plain =
    /port_scan|portscan|portsweep|protocol scan|protocol sweep/.test(l) ? "Port scan: probing for open doors"
    : /icmp sweep/.test(l) ? "Network sweep: looking for live machines"
    : /sql injection/.test(l) ? "Website attack: database break-in"
    : /cross-site scripting|xss/.test(l) ? "Website attack: script injection"
    : /path traversal/.test(l) ? "Website attack: reading private files"
    : /syn flood|request flood|challenge ack/.test(l) ? "Flooding attack"
    : /brute force/.test(l) ? "Password guessing"
    : /terminal server/.test(l) ? "Remote desktop connection attempt"
    : /smb/.test(l) ? "Windows file-sharing probe"
    : /shellcode/.test(l) ? "Possible exploit code"
    : null;
  return plain ? `${plain} — ${m}` : m;
}

/** The kind of activity an alert is about, worked out from a Snort rule message
 *  or a dataset label. Used to give a real plain-English explanation. */
export type Category =
  | "scan" | "dos" | "bruteforce" | "web-sql" | "web-xss" | "web-files"
  | "web" | "botnet" | "exploit" | "rdp" | "smb" | "insider" | "unknown";

export function attackCategory(text: string): Category {
  const l = text.toLowerCase();
  if (/port_scan|portscan|portsweep|protocol scan|protocol sweep|icmp sweep|portscan/.test(l)) return "scan";
  if (/sql injection|union select|or 1=1/.test(l)) return "web-sql";
  if (/cross-site scripting|xss|<script>/.test(l)) return "web-xss";
  if (/path traversal|passwd|directory/.test(l)) return "web-files";
  if (/ddos|syn flood|request flood|challenge ack|\bdos\b|hulk|goldeneye|slowloris|slowhttp/.test(l)) return "dos";
  if (/brute force|ftp|ssh|patator|password/.test(l)) return "bruteforce";
  if (/\bweb\b/.test(l)) return "web";
  if (/\bbot\b|botnet/.test(l)) return "botnet";
  if (/shellcode|overflow|exploit/.test(l)) return "exploit";
  if (/terminal server|rdp|3389/.test(l)) return "rdp";
  if (/smb|netbios|445/.test(l)) return "smb";
  if (/infil/.test(l)) return "insider";
  return "unknown";
}

/** What each kind of activity actually is, in words a non-expert can act on:
 *  what the attacker is trying to do, and whether it is an attack or just a probe. */
export const ATTACK_INFO: Record<Category, { title: string; what: string }> = {
  scan: {
    title: "Port scan (probing for a way in)",
    what: "Something is knocking on thousands of network “doors” on this device to find which services are open. It's the network version of a burglar trying every door and window. On its own it does no damage, but it's the usual first step before a real attack, so it's worth knowing who is doing it.",
  },
  dos: {
    title: "Flooding attack (denial of service)",
    what: "A device is being hit with a flood of traffic meant to overwhelm it so it slows down or stops answering real users. Think of jamming a phone line by calling it non-stop. If a service you run went unresponsive around this time, this is likely why.",
  },
  bruteforce: {
    title: "Password guessing (brute force)",
    what: "Someone is trying to log in over and over with many different passwords, hoping to stumble onto the right one and break into an account. A burst of these against a login (SSH, FTP, a web sign-in) means an account is under active attack.",
  },
  "web-sql": {
    title: "Website attack: database break-in (SQL injection)",
    what: "A request to a website was crafted to trick it into leaking or changing data in its database — for example dumping user records or bypassing a login. This is a direct attempt to steal or tamper with data, not just a probe.",
  },
  "web-xss": {
    title: "Website attack: script injection (XSS)",
    what: "A request tried to smuggle hostile code into a web page so it runs in other visitors' browsers — used to steal sessions or deface pages. It targets the site's users, not the server itself.",
  },
  "web-files": {
    title: "Website attack: reading private files",
    what: "A request tried to escape a website's own folder to read files it shouldn't, such as system password files. It's an attempt to grab information the site was never meant to hand out.",
  },
  web: {
    title: "Website attack",
    what: "A web request matched a known attack pattern — an attempt to abuse a website or web server rather than a normal page visit.",
  },
  botnet: {
    title: "Infected machine (botnet)",
    what: "This traffic looks like a device that's already been taken over and is quietly checking in with an attacker's control server for instructions. If it came from one of your own machines, that machine may be compromised.",
  },
  exploit: {
    title: "Possible exploit code",
    what: "The traffic contains a pattern that matches code used to break into software through a security hole. It's an attempt to seize control of a program, which is more serious than a probe.",
  },
  rdp: {
    title: "Remote desktop connection attempt",
    what: "An outside computer tried to open a Windows Remote Desktop session. This is often normal if you use remote desktop, but a stream of these from unknown addresses is a common break-in attempt.",
  },
  smb: {
    title: "Windows file-sharing probe",
    what: "An outside computer poked at Windows file-sharing (the service behind shared drives). Normal on a trusted office network; suspicious coming from the internet.",
  },
  insider: {
    title: "Insider intrusion",
    what: "Traffic that behaves like an already-inside foothold quietly moving around the network. In this dataset it looks almost identical to normal traffic, which is what makes it hard to catch.",
  },
  unknown: {
    title: "Suspicious connection",
    what: "The traffic behaves differently from normal use in a way that matched an attack pattern, but it doesn't fall into one of the common named categories.",
  },
};

/** One plain sentence describing what a rule/label's activity actually is. */
export const explainActivity = (text: string) => ATTACK_INFO[attackCategory(text)].what;

/** How a detector reached a verdict (the `resolution` field). */
export const RESOLUTIONS: Record<string, { label: string; meaning: string }> = {
  unanimous: { label: "Sure on its own", meaning: "the detector's checks all agreed" },
  advice: { label: "Asked a colleague", meaning: "its checks disagreed, so it took advice from another detector or the rule checker" },
  cross_check: { label: "Double-checked", meaning: "it thought the traffic was safe, but another detector recognised an attack" },
  fallback: { label: "Best guess", meaning: "its checks disagreed and no other detector could help" },
};

export const resolutionLabel = (key: string) => RESOLUTIONS[key]?.label ?? key;

