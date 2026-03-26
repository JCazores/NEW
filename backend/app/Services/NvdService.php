<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * NvdService — Live CVE lookup via NIST NVD API v2
 *
 * Production-grade service used by RunNetworkScan.php to resolve
 * real CVE IDs for any detected software + version combination.
 *
 * Features:
 *  - Live queries to https://services.nvd.nist.gov/rest/json/cves/2.0
 *  - DB-backed cache (cve_cache table) with configurable TTL
 *  - Rate-limit awareness (5 req/30s free, 50/30s with API key)
 *  - Version-range matching — returns CVEs that actually affect the detected version
 *  - CVSS score + severity enrichment from NVD
 *
 * Setup:
 *  Add to .env:
 *    NVD_API_KEY=your-key-here        # optional but strongly recommended
 *    NVD_CACHE_TTL_HOURS=24           # how long to cache results (default 24h)
 *
 *  Get a free API key at: https://nvd.nist.gov/developers/request-an-api-key
 */
class NvdService
{
    private const API_BASE    = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
    private const RESULTS_MAX = 20;   // candidates to fetch per query
    private const TIMEOUT     = 15;   // seconds per HTTP request

    // Rate limiting — sleep between requests to stay within NVD limits
    // Free tier: 5 req/30s = 6s gap. With API key: 50/30s = 0.6s gap.
    private static int $lastRequestAt = 0;

    // ─────────────────────────────────────────────────────────────────────────
    // PUBLIC API
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Look up CVEs for a detected service and version.
     *
     * Returns an array of CVE matches, each with:
     *   id, title, description, cvss, severity, vector, published, references
     *
     * Empty array means no CVEs found or NVD unavailable.
     *
     * @param  string  $product   e.g. "redis", "openssh", "apache httpd"
     * @param  string  $version   e.g. "6.0.20", "7.4", ""
     * @param  int     $limit     max results to return (default 5)
     */
    public function lookup(string $product, string $version = '', int $limit = 5): array
    {
        if (empty(trim($product))) return [];

        $keyword  = $this->buildKeyword($product, $version);
        $cacheKey = 'nvd:' . md5($keyword);
        $ttlHours = (int) config('services.nvd.cache_ttl', 24);

        // ── 1. Check DB cache ────────────────────────────────────────────────
        $cached = $this->fromCache($cacheKey, $ttlHours);
        if ($cached !== null) return $cached;

        // ── 2. Query NVD API ─────────────────────────────────────────────────
        $raw = $this->fetchFromNvd($keyword);
        if (empty($raw)) {
            $this->toCache($cacheKey, []);
            return [];
        }

        // ── 3. Parse + score-rank ────────────────────────────────────────────
        $results = $this->parseAndRank($raw, $version, $limit);

        // ── 4. Cache + return ────────────────────────────────────────────────
        $this->toCache($cacheKey, $results);
        return $results;
    }

    /**
     * Convenience: return just the primary CVE ID string, or null.
     * Use this when you only need the ID to store on the vulnerability record.
     */
    public function primaryCveId(string $product, string $version = ''): ?string
    {
        $results = $this->lookup($product, $version, 1);
        return $results[0]['id'] ?? null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NVD API
    // ─────────────────────────────────────────────────────────────────────────

    private function fetchFromNvd(string $keyword): array
    {
        $this->rateLimit();

        $params = [
            'keywordSearch'  => $keyword,
            'resultsPerPage' => self::RESULTS_MAX,
        ];

        $headers = ['User-Agent' => 'ServerSentinel-VAPT/1.0'];
        $apiKey  = config('services.nvd.api_key');
        if ($apiKey) {
            $headers['apiKey'] = $apiKey;
        }

        try {
            $response = Http::withHeaders($headers)
                ->timeout(self::TIMEOUT)
                ->get(self::API_BASE, $params);

            if (!$response->successful()) {
                Log::warning("[NVD] HTTP {$response->status()} for keyword: {$keyword}");
                return [];
            }

            return $response->json('vulnerabilities') ?? [];

        } catch (\Throwable $e) {
            Log::warning("[NVD] Request failed for '{$keyword}': " . $e->getMessage());
            return [];
        }
    }

    private function parseAndRank(array $vulnerabilities, string $detectedVersion, int $limit): array
    {
        $parsed = [];

        foreach ($vulnerabilities as $item) {
            $cve = $item['cve'] ?? null;
            if (!$cve) continue;

            $id = $cve['id'] ?? null;
            if (!$id) continue;

            // English description
            $desc = '';
            foreach ($cve['descriptions'] ?? [] as $d) {
                if (($d['lang'] ?? '') === 'en') { $desc = $d['value'] ?? ''; break; }
            }

            // CVSS — prefer v3.1, fall back to v3.0, then v2
            $metrics  = $cve['metrics'] ?? [];
            $cvssData = $metrics['cvssMetricV31'][0]
                ?? $metrics['cvssMetricV30'][0]
                ?? $metrics['cvssMetricV2'][0]
                ?? null;

            $cvssScore  = null;
            $cvssVector = null;
            $severity   = 'medium';

            if ($cvssData) {
                $d          = $cvssData['cvssData'] ?? $cvssData;
                $cvssScore  = isset($d['baseScore'])    ? (float)  $d['baseScore']    : null;
                $cvssVector = $d['vectorString'] ?? null;
                $rawSev     = strtolower($d['baseSeverity'] ?? $cvssData['baseSeverity'] ?? '');
                $severity   = in_array($rawSev, ['critical','high','medium','low']) ? $rawSev : $this->scoreTo($cvssScore);
            }

            // References (top 5)
            $refs = array_slice(
                array_map(fn($r) => $r['url'] ?? '', $cve['references'] ?? []),
                0, 5
            );

            $published = isset($cve['published']) ? substr($cve['published'], 0, 10) : null;

            // Version range relevance score (higher = better match)
            $relevance = $this->versionRelevance($cve, $detectedVersion);

            $parsed[] = [
                'id'          => $id,
                'title'       => $this->titleFromDesc($desc),
                'description' => $desc,
                'cvss'        => $cvssScore,
                'severity'    => $severity,
                'vector'      => $cvssVector,
                'published'   => $published,
                'references'  => array_filter($refs),
                '_relevance'  => $relevance,
            ];
        }

        // Sort: relevance desc, then cvss desc, then published desc
        usort($parsed, function ($a, $b) {
            if ($b['_relevance'] !== $a['_relevance']) return $b['_relevance'] <=> $a['_relevance'];
            if ($b['cvss'] !== $a['cvss'])             return ($b['cvss'] ?? 0) <=> ($a['cvss'] ?? 0);
            return strcmp($b['published'] ?? '', $a['published'] ?? '');
        });

        // Strip internal ranking field and return top N
        return array_map(function ($r) {
            unset($r['_relevance']);
            return $r;
        }, array_slice($parsed, 0, $limit));
    }

    /**
     * Score how relevant a CVE is to the detected version.
     * Returns 2 = version explicitly in affected range
     *         1 = version mentioned in description
     *         0 = no version info
     */
    private function versionRelevance(array $cve, string $detectedVersion): int
    {
        if (empty($detectedVersion)) return 0;

        $ver = $this->parseVersion($detectedVersion);
        if (!$ver) return 0;

        // Check CPE match configurations
        foreach ($cve['configurations'] ?? [] as $config) {
            foreach ($config['nodes'] ?? [] as $node) {
                foreach ($node['cpeMatch'] ?? [] as $cpe) {
                    $start = $cpe['versionStartIncluding'] ?? $cpe['versionStartExcluding'] ?? null;
                    $end   = $cpe['versionEndIncluding']   ?? $cpe['versionEndExcluding']   ?? null;

                    if ($start && $end) {
                        if (version_compare($ver, $start, '>=') && version_compare($ver, $end, '<=')) {
                            return 2; // confirmed in range
                        }
                    } elseif ($end && version_compare($ver, $end, '<=')) {
                        return 2;
                    }
                }
            }
        }

        // Fallback: check if version string appears in description
        $desc = '';
        foreach ($cve['descriptions'] ?? [] as $d) {
            if (($d['lang'] ?? '') === 'en') { $desc = $d['value'] ?? ''; break; }
        }
        if ($ver && str_contains($desc, $detectedVersion)) return 1;

        return 0;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CACHE (DB-backed)
    // ─────────────────────────────────────────────────────────────────────────

    private function fromCache(string $key, int $ttlHours): ?array
    {
        try {
            $row = DB::table('cve_cache')
                ->where('cache_key', $key)
                ->where('expires_at', '>', now())
                ->first();

            if ($row) return json_decode($row->payload, true) ?? [];
        } catch (\Throwable $e) {
            Log::debug('[NVD] Cache read failed: ' . $e->getMessage());
        }
        return null;
    }

    private function toCache(string $key, array $data): void
    {
        $ttlHours = (int) config('services.nvd.cache_ttl', 24);
        try {
            DB::table('cve_cache')->upsert(
                [
                    'cache_key'  => $key,
                    'payload'    => json_encode($data),
                    'expires_at' => now()->addHours($ttlHours),
                    'created_at' => now(),
                    'updated_at' => now(),
                ],
                ['cache_key'],
                ['payload', 'expires_at', 'updated_at']
            );
        } catch (\Throwable $e) {
            Log::debug('[NVD] Cache write failed: ' . $e->getMessage());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RATE LIMITING
    // ─────────────────────────────────────────────────────────────────────────

    private function rateLimit(): void
    {
        $hasKey   = (bool) config('services.nvd.api_key');
        $minGapMs = $hasKey ? 700 : 6100; // ms between requests

        $now     = (int) (microtime(true) * 1000);
        $elapsed = $now - self::$lastRequestAt;

        if (self::$lastRequestAt > 0 && $elapsed < $minGapMs) {
            usleep(($minGapMs - $elapsed) * 1000);
        }

        self::$lastRequestAt = (int) (microtime(true) * 1000);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HELPERS
    // ─────────────────────────────────────────────────────────────────────────

    private function buildKeyword(string $product, string $version): string
    {
        $p = strtolower(trim($product));

        // Normalise common product names to what NVD uses
        $aliases = [
            'apache httpd'   => 'apache http server',
            'httpd'          => 'apache http server',
            'openssh'        => 'openssh',
            'microsoft-ds'   => 'windows smb',
            'netbios-ssn'    => 'windows smb',
            'ms-wbt-server'  => 'remote desktop protocol',
            'ms-sql-s'       => 'microsoft sql server',
            'postgresql'     => 'postgresql',
            'redis'          => 'redis',
            'mongodb'        => 'mongodb',
        ];

        foreach ($aliases as $needle => $replacement) {
            if (str_contains($p, $needle)) { $p = $replacement; break; }
        }

        // Include major.minor version in keyword for better NVD matching
        $ver = $this->parseVersion($version);
        $kw  = $ver ? "{$p} {$ver}" : $p;

        return trim($kw);
    }

    private function parseVersion(string $v): ?string
    {
        if (preg_match('/(\d+\.\d+(?:\.\d+)?)/', $v, $m)) return $m[1];
        return null;
    }

    private function scoreTo(?float $score): string
    {
        if ($score === null) return 'medium';
        if ($score >= 9.0)  return 'critical';
        if ($score >= 7.0)  return 'high';
        if ($score >= 4.0)  return 'medium';
        return 'low';
    }

    private function titleFromDesc(string $desc): string
    {
        // Extract a short title from the first sentence of the NVD description
        $first = explode('.', $desc)[0];
        $title = preg_replace('/^(A|An|The)\s+/i', '', $first);
        return strlen($title) > 80 ? substr($title, 0, 77) . '...' : ucfirst(trim($title));
    }
}