import { NextApiRequest, NextApiResponse } from 'next';

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
  name?: string;
  version?: string;
}

interface ScanResult {
  issues: string[];
}

export const config = {
  api: {
    bodyParser: {
      sizeLimit: '1mb',
    },
  },
};

// Malicious NPM Packages
const KNOWN_MALICIOUS_PACKAGES = [
  "event-stream", "crossenv", "fallguys", "bignum", "electron-native-notify",
  "1337qq-js", "shelljs", "jacking", "web3_eth", "discord.dll",
  "electronic-pdf", "ionicio", "travis-prebuild", "twilio-npm",
  "fix-error", "npm-diversity", "amzn", "pyexec", "jobprovider",
  "websocket_sync", "new-x", "beta-simulator", "lucky-loader",
  "small-npm-package", "shadow-crypto", "discord.js-protect",
  "eth-wallet-backdoor", "libsearch"
];

// Malicious Deno Packages
const KNOWN_MALICIOUS_DENO = [
  "deno-malware", "deno-exploit", "deno-badlib", "deno-virus",
  "deno-trojan", "deno-backdoor", "deno-webhook-stealer",
  "deno-env-logger", "deno-remote-exec", "deno-shell-hijack"
];

// Malicious Script Patterns (Expanded)
const MALICIOUS_SCRIPTS = /(curl|wget|rm -rf|base64|eval|exec|child_process|netcat|nc|bash|sh|python|perl|node|php|os\.system|new Function|setTimeout|Buffer\.from)/i;

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<ScanResult | { error: string }>
): Promise<void> {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  try {
    const { packageJson } = req.body as { packageJson: PackageJson };

    if (!packageJson || (!packageJson.dependencies && !packageJson.devDependencies)) {
      return res.status(400).json({ error: 'Invalid package.json format' });
    }

    console.log("📦 Scanning package.json:", packageJson);

    const issues = scanPackageJson(packageJson);

    console.log("🔎 Scan completed. Issues found:", issues);

    return res.status(200).json({ issues });
  } catch (error) {
    console.error("🔥 Error in API handler:", error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
}

function scanPackageJson(packageJson: PackageJson): string[] {
  const issues: string[] = [];

  if (!packageJson.name || !packageJson.version) {
    issues.push('⚠️ Invalid package.json: Missing name or version.');
  }

  // Scan for malicious scripts
  if (packageJson.scripts) {
    for (const [scriptName, script] of Object.entries(packageJson.scripts)) {
      if (MALICIOUS_SCRIPTS.test(script)) {
        issues.push(`🚨 Suspicious script detected in '${scriptName}': ${script}`);
      }
    }
  }

  // Scan Dependencies for Malicious Packages
  const allDependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };
  for (const pkg of Object.keys(allDependencies)) {
    if (KNOWN_MALICIOUS_PACKAGES.includes(pkg)) {
      issues.push(`🚨 Malicious package detected: ${pkg}`);
    }
    if (KNOWN_MALICIOUS_DENO.includes(pkg)) {
      issues.push(`🚨 Known malicious Deno package detected: ${pkg}`);
    }
  }

  // Ensure frontend receives correct response
  if (issues.length === 0) {
    return ['✅ No security issues found.'];
  } else {
    return issues;
  }
}
