<?php

namespace App\Jobs;

use App\Models\VaptScan;
use App\Models\VaptVulnerability;
use App\Services\NvdService;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class RunNetworkScan implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $timeout = 600;

    private array $log = [];
    private NvdService $nvd;

    /**
     * Top vulnerable ports used for 'vuln' scan type.
     * Replaces the previous -p- (all 65535 ports) which caused extreme slowness.
     * These 30 ports cover ~95% of real-world network vulnerabilities.
     */
    private const VULN_PORTS = '21,22,23,25,53,80,110,111,135,139,143,161,443,445,512,513,514,993,995,1433,1521,2049,2375,3306,3389,5432,5900,6379,8080,8161,9200,27017';

    public function __construct(public VaptScan $scan)
    {
        $this->nvd = new NvdService();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PHASE TRACKING — frontend polls /scans/{id}/status in real time
    // ─────────────────────────────────────────────────────────────────────────

    private function phase(string $label, int $progress, string $detail = ''): void
    {
        $entry = [
            'time'     => now()->format('H:i:s'),
            'phase'    => $label,
            'detail'   => $detail,
            'progress' => $progress,
        ];
        $this->log[] = $entry;

        $this->scan->update([
            'phase'     => $label,
            'progress'  => $progress,
            'phase_log' => json_encode($this->log),
        ]);

        Log::info("[Scan #{$this->scan->id}] {$progress}% — {$label}" . ($detail ? ": {$detail}" : ''));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ENTRY POINT
    // ─────────────────────────────────────────────────────────────────────────

    public function handle(): void
    {
        $this->scan->update(['status' => 'running', 'progress' => 0]);
        $this->phase('Initializing', 2, "Target: {$this->scan->target} | Type: {$this->scan->scan_type}");

        try {
            // Step 1: Host Discovery + Port Scan
            $this->phase('Host Discovery', 10, "Pinging {$this->scan->target} to check if host is alive");
            $hosts = $this->runDiscovery();

            if (empty($hosts)) {
                $this->phase('No Hosts Found', 100, "Target {$this->scan->target} appears to be offline or blocking scans");
                $this->autoResolvePreviousVulns([]);
                $this->scan->update(['status' => 'done']);
                return;
            }

            $hostList = implode(', ', array_column($hosts, 'ip'));
            $this->phase('Hosts Found', 25, "Live hosts: {$hostList}");

            // Step 2: Vuln scripts (only for 'vuln' scan type)
            if ($this->scan->scan_type === 'vuln') {
                $this->phase('Running Vulnerability Scripts', 40, 'Running targeted Nmap NSE scripts per service...');
                $hosts = $this->runVulnScripts($hosts);
                $this->phase('Scripts Complete', 65, 'NSE script execution finished');
            }

            // Step 3: Analyze
            $this->phase('Analyzing Results', 75, 'Matching service versions against CVE database...');
            $findings = $this->analyzeHosts($hosts);
            $this->phase('Analysis Complete', 88, count($findings) . ' potential finding(s) identified');

            // Step 4: Save
            $this->phase('Saving to Database', 93, 'Deduplicating and storing vulnerabilities...');
            $saved = $this->saveFindings($findings);
            $this->phase('Complete', 100, "{$saved} vulnerability record(s) saved");

            // Step 5: Auto-resolve previous open vulns if this scan is clean
            $this->autoResolvePreviousVulns($findings);

            $this->scan->update(['status' => 'done']);

        } catch (\Throwable $e) {
            $this->phase('Failed', 0, $e->getMessage());
            Log::error("Scan #{$this->scan->id} failed: " . $e->getMessage());
            $this->scan->update(['status' => 'failed', 'error_message' => $e->getMessage()]);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // STEP 1 — DISCOVERY
    // ─────────────────────────────────────────────────────────────────────────

    private function runDiscovery(): array
    {
        $rawTarget = preg_replace('/:\d+$/', '', trim($this->scan->target));
        $target    = escapeshellarg($rawTarget);

        // ── FIX: vuln scan no longer uses -p- (all 65535 ports = very slow)
        //    Instead it scans a curated list of the most commonly vulnerable ports.
        //    quick = top 100 ports (-F)
        //    full  = all ports (-p-)
        //    vuln  = targeted vulnerable ports (fast + thorough for real threats)
        $portFlags = match ($this->scan->scan_type) {
            'quick'  => '-F',
            'full'   => '-p-',
            'vuln'   => '-p ' . self::VULN_PORTS,
            default  => '-F',
        };

        $this->phase('Port Scanning', 15, "Running: nmap {$portFlags} -sV on {$rawTarget}");

        $cmd = "/usr/bin/nmap {$portFlags} -sV -sC --version-intensity 7 -T4 --host-timeout 120s -oX - {$target} 2>/dev/null";
        $xml = shell_exec($cmd);

        if (empty($xml) || !str_contains($xml, '<nmaprun')) {
            throw new \RuntimeException("Nmap returned no output for: {$rawTarget}");
        }

        $hosts = $this->parseDiscoveryXml($xml);

        foreach ($hosts as $host) {
            $ports = array_column($host['ports'], 'portid');
            $this->phase('Service Detection', 20,
                "Host {$host['ip']}: found " . count($ports) . " open port(s): " . implode(', ', $ports));
        }

        return $hosts;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // STEP 2 — VULN SCRIPTS
    // ─────────────────────────────────────────────────────────────────────────

    private function runVulnScripts(array $hosts): array
    {
        $serviceScripts = [
            'http'         => 'http-vuln-cve2010-0738,http-vuln-cve2011-3192,http-vuln-cve2017-5638,http-shellshock,http-slowloris-check',
            'https'        => 'ssl-heartbleed,ssl-poodle,ssl-ccs-injection,ssl-dh-params,ssl-cert',
            'ssl'          => 'ssl-heartbleed,ssl-poodle,ssl-ccs-injection,ssl-dh-params',
            'ftp'          => 'ftp-anon,ftp-vuln-cve2010-4221,ftp-proftpd-backdoor,ftp-vsftpd-backdoor',
            'ssh'          => 'ssh-auth-methods,ssh2-enum-algos',
            'smtp'         => 'smtp-open-relay,smtp-vuln-cve2010-4344',
            'smb'          => 'smb-vuln-ms17-010,smb-vuln-cve-2020-0796,smb-vuln-ms08-067,smb-security-mode',
            'microsoft-ds' => 'smb-vuln-ms17-010,smb-vuln-cve-2020-0796',
            'mysql'        => 'mysql-empty-password,mysql-vuln-cve2012-2122',
            'rdp'          => 'rdp-vuln-ms12-020,rdp-enum-encryption',
            'redis'        => 'redis-info',
            'mongodb'      => 'mongodb-info',
            'snmp'         => 'snmp-info',
        ];

        $scriptTargets = [];
        foreach ($hosts as $host) {
            foreach ($host['ports'] as $port) {
                $svc = strtolower($port['service']);
                foreach ($serviceScripts as $key => $scripts) {
                    if (str_contains($svc, $key)) {
                        $scriptTargets[$scripts][] = ['ip' => $host['ip'], 'port' => $port['portid']];
                        break;
                    }
                }
            }
        }

        $total = count($scriptTargets);
        $done  = 0;
        foreach ($scriptTargets as $scripts => $targets) {
            $portList   = implode(',', array_unique(array_column($targets, 'port')));
            $ips        = implode(' ', array_unique(array_map(fn($t) => escapeshellarg($t['ip']), $targets)));
            $scriptName = explode(',', $scripts)[0];
            $this->phase('Running Scripts', 40 + (int)(25 * $done / max($total, 1)),
                "Script: {$scriptName} on port(s) {$portList}");

            $cmd = "/usr/bin/nmap -p {$portList} --script={$scripts} --script-timeout 30s -T4 --host-timeout 90s -oX - {$ips} 2>/dev/null";
            $xml = shell_exec($cmd);

            if (!empty($xml) && str_contains($xml, '<nmaprun')) {
                $scriptHosts = $this->parseDiscoveryXml($xml);
                foreach ($scriptHosts as $sHost) {
                    foreach ($hosts as &$host) {
                        if ($host['ip'] === $sHost['ip']) {
                            foreach ($sHost['ports'] as $sPort) {
                                foreach ($host['ports'] as &$port) {
                                    if ($port['portid'] === $sPort['portid']) {
                                        $port['scripts'] = array_merge($port['scripts'] ?? [], $sPort['scripts'] ?? []);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            $done++;
        }

        return $hosts;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // STEP 3 — ANALYZE
    // ─────────────────────────────────────────────────────────────────────────

    private function analyzeHosts(array $hosts): array
    {
        $findings = [];
        foreach ($hosts as $host) {
            $ip = $host['ip'];
            foreach ($host['ports'] as $port) {
                $portNum = $port['portid'];
                $service = $port['service'];
                $product = $port['product'] ?? '';
                $version = $port['version'] ?? '';
                $scripts = $port['scripts'] ?? [];

                if ($product || $version) {
                    $this->phase('CVE Matching', 78,
                        "Checking {$product} {$version} on {$ip}:{$portNum} against CVE database");
                }

                foreach ($scripts as $script) {
                    $vulns    = $this->parseScriptOutput($ip, $portNum, $service, $product, $version, $script);
                    $findings = array_merge($findings, $vulns);
                }

                $versionVulns = $this->matchVersionCves($ip, $portNum, $service, $product, $version);
                $findings     = array_merge($findings, $versionVulns);

                $configRisks = $this->checkConfigRisks($ip, $portNum, $service, $product, $version);
                $findings    = array_merge($findings, $configRisks);
            }
        }
        return $findings;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CVE DATABASE
    // ─────────────────────────────────────────────────────────────────────────

    private function matchVersionCves(string $ip, int $port, string $service, string $product, string $version): array
    {
        if (empty($product) && empty($version)) return [];

        try {
            $results = $this->nvd->lookup($product, $version, 3);
        } catch (\Throwable $e) {
            Log::debug("[NVD] matchVersionCves failed for {$product} {$version}: " . $e->getMessage());
            return [];
        }

        $findings = [];
        foreach ($results as $cve) {
            $findings[] = $this->finding(
                $ip, $port, $service,
                $cve['id'],
                $cve['title'],
                $cve['description'],
                $cve['cvss'] ?? 5.0,
                $cve['severity'] ?? 'medium'
            );
        }
        return $findings;
    }

    private function checkConfigRisks(string $ip, int $port, string $service, string $product, string $version): array
    {
        $RISKS = [
            23    => ['title' => 'Telnet Open',               'sev' => 'critical', 'cvss' => 9.8, 'search' => 'telnet plaintext credentials',            'desc' => 'Telnet transmits credentials in plaintext. Replace with SSH immediately.'],
            21    => ['title' => 'FTP Open',                  'sev' => 'high',     'cvss' => 7.5, 'search' => 'ftp cleartext credentials',               'desc' => 'FTP transmits data and credentials in cleartext. Use SFTP or FTPS.'],
            445   => ['title' => 'SMB Exposed',               'sev' => 'high',     'cvss' => 8.1, 'search' => 'windows smb remote code execution',       'desc' => 'SMB port exposed. May be vulnerable to EternalBlue if unpatched.'],
            3389  => ['title' => 'RDP Exposed',               'sev' => 'high',     'cvss' => 7.5, 'search' => 'remote desktop protocol remote code',     'desc' => 'RDP exposed. Verify BlueKeep patch status. Restrict behind VPN.'],
            3306  => ['title' => 'MySQL Port Exposed',        'sev' => 'high',     'cvss' => 7.2, 'search' => 'mysql unauthorized access',               'desc' => 'MySQL directly accessible. Should not be publicly exposed.'],
            5432  => ['title' => 'PostgreSQL Exposed',        'sev' => 'high',     'cvss' => 7.2, 'search' => 'postgresql unauthorized access',          'desc' => 'PostgreSQL directly accessible. Restrict to app servers only.'],
            6379  => ['title' => 'Redis Exposed (No Auth)',   'sev' => 'critical', 'cvss' => 9.8, 'search' => 'redis no authentication remote code',     'desc' => 'Redis has no auth by default. Full read/write access. Bind to localhost.'],
            27017 => ['title' => 'MongoDB Exposed (No Auth)', 'sev' => 'critical', 'cvss' => 9.8, 'search' => 'mongodb no authentication exposed',       'desc' => 'MongoDB exposed without authentication. Full database access risk.'],
            9200  => ['title' => 'Elasticsearch Exposed',    'sev' => 'critical', 'cvss' => 9.8, 'search' => 'elasticsearch unauthorized access',       'desc' => 'Elasticsearch exposed without auth. All indexed data is readable.'],
            2375  => ['title' => 'Docker API Exposed',        'sev' => 'critical', 'cvss' => 9.8, 'search' => 'docker api exposed remote code',          'desc' => 'Docker daemon API exposed without TLS. Full container/host control possible.'],
            161   => ['title' => 'SNMP Exposed',              'sev' => 'medium',   'cvss' => 5.3, 'search' => 'snmp information disclosure',             'desc' => 'SNMP may leak network topology. Use SNMPv3 with authentication.'],
            5900  => ['title' => 'VNC Exposed',               'sev' => 'high',     'cvss' => 7.2, 'search' => 'vnc authentication bypass remote',        'desc' => 'VNC exposed. May have weak/no authentication. Restrict behind VPN.'],
            2049  => ['title' => 'NFS Exposed',               'sev' => 'high',     'cvss' => 7.5, 'search' => 'nfs no authentication file access',       'desc' => 'NFS shares may be accessible without authentication.'],
            1433  => ['title' => 'MSSQL Port Exposed',        'sev' => 'high',     'cvss' => 7.2, 'search' => 'microsoft sql server unauthorized',       'desc' => 'MSSQL directly accessible. Restrict to app servers only.'],
            512   => ['title' => 'RSH/Rexec Service',         'sev' => 'critical', 'cvss' => 9.8, 'search' => 'rsh rexec no authentication remote',      'desc' => 'Legacy rsh/rexec — no encryption, no authentication. Disable immediately.'],
            8161  => ['title' => 'ActiveMQ Admin Console',    'sev' => 'critical', 'cvss' => 9.8, 'search' => 'apache activemq remote code execution',   'desc' => 'ActiveMQ admin console exposed. Potentially vulnerable to RCE.'],
        ];

        if (!isset($RISKS[$port])) return [];
        $r = $RISKS[$port];

        // Always look up the real CVE from NVD — use detected product+version if available,
        // otherwise use the search term for this port
        $cveId = null;
        try {
            $searchProduct = !empty($product) ? $product : $r['search'];
            $cveId = $this->nvd->primaryCveId($searchProduct, $version ?? '');
        } catch (\Throwable $e) {
            Log::debug("[NVD] Config risk CVE lookup failed for port {$port}: " . $e->getMessage());
        }

        return [$this->finding($ip, $port, $service, $cveId, $r['title'],
            $r['desc'] . ($product ? " (Detected: {$product}" . ($version ? " {$version}" : '') . ")" : ""),
            $r['cvss'], $r['sev'])];
    }

    private function parseScriptOutput(string $ip, int $port, string $service, string $product, string $version, array $script): array
    {
        $id     = $script['id']     ?? '';
        $output = $script['output'] ?? '';
        if (stripos($output, 'VULNERABLE') === false) return [];

        $cveId = null;
        if (preg_match('/(CVE-\d{4}-\d{4,})/i', $output, $m)) $cveId = strtoupper($m[1]);
        $cvss = null;
        if (preg_match('/cvss\s*:\s*([\d.]+)/i', $output, $m)) $cvss = (float) $m[1];
        $severity = $this->cvssToSeverity($cvss);
        if (preg_match('/Risk factor\s*:\s*(\w+)/i', $output, $m)) {
            $severity = ['critical'=>'critical','high'=>'high','medium'=>'medium','low'=>'low'][strtolower($m[1])] ?? $severity;
        }
        return [$this->finding($ip, $port, $service, $cveId, $this->scriptIdToTitle($id),
            $this->extractScriptDesc($output), $cvss ?? 5.0, $severity)];
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PARSE XML
    // ─────────────────────────────────────────────────────────────────────────

    private function parseDiscoveryXml(string $xml): array
    {
        $hosts = [];
        try { $doc = new \SimpleXMLElement($xml); } catch (\Exception $e) { return []; }
        foreach ($doc->host as $host) {
            if ((string) $host->status['state'] !== 'up') continue;
            $ip = '';
            foreach ($host->address as $addr) {
                if ((string) $addr['addrtype'] === 'ipv4') { $ip = (string) $addr['addr']; break; }
            }
            if (!$ip || !isset($host->ports->port)) continue;
            $ports = [];
            foreach ($host->ports->port as $port) {
                if ((string) $port->state['state'] !== 'open') continue;
                $scripts = [];
                foreach ($port->script as $s) {
                    $scripts[] = ['id' => (string) $s['id'], 'output' => (string) $s['output']];
                }
                $ports[] = [
                    'portid'  => (int)    $port['portid'],
                    'service' => (string)($port->service['name']    ?? 'unknown'),
                    'product' => (string)($port->service['product'] ?? ''),
                    'version' => (string)($port->service['version'] ?? ''),
                    'scripts' => $scripts,
                ];
            }
            if (!empty($ports)) $hosts[] = ['ip' => $ip, 'ports' => $ports];
        }
        return $hosts;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // AUTO-RESOLVE
    // If this scan found zero vulnerabilities on a host that previously had
    // open vulnerabilities, those are automatically marked as resolved.
    // This runs after saveFindings() so we can compare against the new results.
    // ─────────────────────────────────────────────────────────────────────────

    private function autoResolvePreviousVulns(array $findings): void
{
    // Hosts that actually have NEW saved vulnerabilities in THIS scan
    $activeHosts = VaptVulnerability::where('scan_id', $this->scan->id)
        ->pluck('host')
        ->unique()
        ->values()
        ->all();

    // Find ALL previous scan IDs for the same target
    $previousScanIds = VaptScan::where('target', $this->scan->target)
        ->where('scan_type', $this->scan->scan_type)
        ->where('id', '!=', $this->scan->id)
        ->pluck('id')
        ->all();

    if (empty($previousScanIds)) return;

    // Get hosts that have open vulns in previous scans
    $previousHosts = VaptVulnerability::whereIn('scan_id', $previousScanIds)
        ->where('status', 'open')
        ->pluck('host')
        ->unique()
        ->all();

    // Any host that had open vulns before but has NO new findings in this scan = auto-resolve
    $cleanHosts = array_diff($previousHosts, $activeHosts);

    if (empty($cleanHosts)) return;

    $resolved = VaptVulnerability::whereIn('scan_id', $previousScanIds)
        ->whereIn('host', $cleanHosts)
        ->where('status', 'open')
        ->update(['status' => 'resolved']);

    if ($resolved > 0) {
        $hostList = implode(', ', $cleanHosts);
        $this->phase('Auto-Resolved', 100,
            "{$resolved} previous vulnerabilit" . ($resolved === 1 ? 'y' : 'ies') .
            " auto-resolved — clean scan on: {$hostList}");

        Log::info("[Scan #{$this->scan->id}] Auto-resolved {$resolved} vulnerabilities on clean hosts: {$hostList}");
    }
}

    // ─────────────────────────────────────────────────────────────────────────
    // SAVE
    // ─────────────────────────────────────────────────────────────────────────

    // ─────────────────────────────────────────────────────────────────────────
    // SAVE — deduplicates across all scans of the same target
    // If the same host:port:title was found before (any scan of this target),
    // we re-open it on the current scan instead of creating a duplicate record.
    // ─────────────────────────────────────────────────────────────────────────

    private function saveFindings(array $findings): int
    {
        if (empty($findings)) return 0;

        // All previous scan IDs for this target (excluding current)
        $previousScanIds = VaptScan::where('target', $this->scan->target)
            ->where('scan_type', $this->scan->scan_type)
            ->where('id', '!=', $this->scan->id)
            ->pluck('id')
            ->all();

        $saved = 0;
        foreach ($findings as $f) {
            // Check if this exact finding already exists in a previous scan
            $existing = null;
            if (!empty($previousScanIds)) {
                $existing = VaptVulnerability::whereIn('scan_id', $previousScanIds)
                    ->where('host',  $f['host'])
                    ->where('port',  $f['port'])
                    ->where('title', $f['title'])
                    ->first();
            }

            if ($existing) {
                // Move it to current scan and re-open it
                $existing->update([
                    'scan_id'     => $this->scan->id,
                    'status'      => 'open',
                    'cve_id'      => $f['cve_id']      ?? $existing->cve_id,
                    'severity'    => $f['severity']    ?? $existing->severity,
                    'cvss'        => $f['cvss']        ?? $existing->cvss,
                    'description' => $f['description'] ?? $existing->description,
                ]);
                $saved++;
            } else {
                // Brand new finding
                VaptVulnerability::create([
                    'scan_id'     => $this->scan->id,
                    'host'        => $f['host'],
                    'port'        => $f['port'],
                    'service'     => $f['service'],
                    'title'       => $f['title'],
                    'cve_id'      => $f['cve_id'],
                    'severity'    => $f['severity'],
                    'description' => $f['description'],
                    'cvss'        => $f['cvss'],
                    'status'      => 'open',
                ]);
                $saved++;
            }
        }
        return $saved;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HELPERS
    // ─────────────────────────────────────────────────────────────────────────

    private function finding(string $ip, int $port, string $service, ?string $cve, string $title, string $desc, float $cvss, string $severity): array
    {
        return ['host' => $ip, 'port' => $port, 'service' => $service, 'cve_id' => $cve,
                'title' => $title, 'description' => $desc, 'cvss' => $cvss, 'severity' => $severity];
    }

    private function cvssToSeverity(?float $cvss): string
    {
        if ($cvss === null) return 'medium';
        if ($cvss >= 9.0)  return 'critical';
        if ($cvss >= 7.0)  return 'high';
        if ($cvss >= 4.0)  return 'medium';
        return 'low';
    }

    private function parseVersion(string $v): ?string
    {
        if (preg_match('/(\d+\.\d+[\.\d]*)/', $v, $m)) return $m[1];
        return null;
    }

    private function scriptIdToTitle(string $id): string
    {
        $map = [
            'ssl-heartbleed'         => 'Heartbleed (CVE-2014-0160)',
            'ssl-poodle'             => 'POODLE SSLv3 Downgrade',
            'ssl-dh-params'          => 'Weak Diffie-Hellman (Logjam)',
            'smb-vuln-ms17-010'      => 'EternalBlue MS17-010',
            'ftp-anon'               => 'FTP Anonymous Login Enabled',
            'ftp-vsftpd-backdoor'    => 'vsftpd 2.3.4 Backdoor',
            'http-shellshock'        => 'Shellshock (CVE-2014-6271)',
            'mysql-empty-password'   => 'MySQL Empty Password',
            'http-vuln-cve2017-5638' => 'Apache Struts RCE (CVE-2017-5638)',
        ];
        return $map[$id] ?? ucwords(str_replace(['-', '_'], ' ', $id));
    }

    private function extractScriptDesc(string $output): string
    {
        $lines  = array_filter(array_map('trim', explode("\n", $output)),
            fn($l) => strlen($l) > 5 && !str_starts_with($l, '*') && !str_starts_with($l, '+'));
        $useful = array_slice(array_values($lines), 0, 4);
        return implode(' ', $useful);
    }
}