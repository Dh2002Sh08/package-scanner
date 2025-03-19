import { NextApiRequest, NextApiResponse } from 'next';
import { exec } from 'child_process';
import util from 'util';
import fetch from 'node-fetch';

const execPromise = util.promisify(exec);

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

const knownDenoPackages = new Set();

async function updateDenoPackages() {
  try {
    const response = await fetch('https://apiland.deno.dev/v2/modules');
    const data = await response.json() as { items: { name: string }[] };
    data.items.forEach((pkg) => knownDenoPackages.add(pkg.name));
  } catch (error) {
    console.error('Error fetching Deno packages:', error);
  }
}
updateDenoPackages();

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<ScanResult | { error: string }>
): Promise<void> {
  if (req.method === 'POST') {
    try {
      const { packageJson } = req.body as { packageJson: PackageJson };
      const result = await scanPackageJson(packageJson);
      res.status(200).json(result);
    } catch (error) {
      console.error('Error processing the request:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  } else {
    res.status(405).json({ error: 'Method Not Allowed' });
  }
}

async function scanPackageJson(packageJson: PackageJson): Promise<ScanResult> {
  const issues = await runScan(packageJson);
  return {
    issues: issues.length ? issues : ['No issues found'],
  };
}

async function runScan(packageJson: PackageJson): Promise<string[]> {
  const issues: string[] = [];

  // Check package.json format
  if (!packageJson.name || !packageJson.version) {
    issues.push('Invalid package.json: Missing name or version.');
  }

  // Detect suspicious scripts
  if (packageJson.scripts) {
    for (const [key, script] of Object.entries(packageJson.scripts)) {
      if (/curl|wget|rm -rf|base64|eval|exec|setTimeout|setInterval|fs.writeFileSync|child_process|netcat|nc|bash|sh|powershell|python|perl|node|java|lua|ruby|php|openssl|env|ncat|socat|reverse shell|crypto|dns|http|get|post|fetch|axios|request|XMLHttpRequest|document.write/i.test(script)) {
        issues.push(`Suspicious script detected in ${key}: ${script}`);
      }
    }
  }

  // Validate dependencies & detect malicious packages
  if (packageJson.dependencies) {
    for (const [pkg, version] of Object.entries(packageJson.dependencies)) {
      if (!/^\d+\.\d+\.\d+$/.test(version) && !/^[~^]\d+\.\d+\.\d+$/.test(version)) {
        issues.push(`Invalid version format for ${pkg}: ${version}`);
      }
      if (await isMaliciousPackage(pkg)) {
        issues.push(`Potentially malicious package detected: ${pkg}. Always download from official sources like npmjs.com.`);
      }
    }
  }

  // Run npm audit
  try {
    const { stdout } = await execPromise('npm audit --json');
    const auditResults = JSON.parse(stdout);
    if (auditResults.vulnerabilities) {
      for (const key in auditResults.vulnerabilities) {
        const vuln = auditResults.vulnerabilities[key];
        issues.push(`npm audit: ${vuln.name || key} (${vuln.severity || 'unknown severity'})`);
      }
    }
  } catch (error) {
    console.error('Error running npm audit:', error);
    issues.push('Failed to run npm audit.');
  }

  // Run Deno security check
  if (packageJson.dependencies) {
    for (const pkg of Object.keys(packageJson.dependencies)) {
      if (await isDenoMaliciousPackage(pkg)) {
        issues.push(`Deno security alert: Potential malicious package detected: ${pkg}. Only use packages from deno.land/x.`);
      }
    }
  }

  return issues;
}

async function isMaliciousPackage(pkg: string): Promise<boolean> {
  try {
    const response = await fetch(`https://registry.npmjs.org/${pkg}`);
    if (!response.ok) return true; // If package does not exist, flag it as suspicious
    const data = await response.json() as { versions: Record<string, { dist: { tarball: string } }> };
    return data.versions && Object.keys(data.versions).length === 0;
  } catch (error) {
    console.error(`Error checking package ${pkg}:`, error);
    return true;
  }
}

async function isDenoMaliciousPackage(pkg: string): Promise<boolean> {
  if (!knownDenoPackages.has(pkg)) return false; // Ignore non-Deno packages
  try {
    const response = await fetch(`https://deno.land/x/${pkg}/mod.ts`);
    return response.status !== 200;
  } catch (error) {
    console.error(`Error checking Deno package ${pkg}:`, error);
    return true;
  }
}
