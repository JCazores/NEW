<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class VulnSightBridgeController extends Controller
{
    private string $baseUrl;
    private string $bridgeSecret;

    public function __construct()
    {
        $this->baseUrl = rtrim(env('VULNSIGHT_URL', 'http://localhost:8001'), '/');
        $this->bridgeSecret = env('VULNSIGHT_BRIDGE_SECRET', 'supersecrettoken123');
    }

    // POST /api/vapt/connect-vulnsight
    public function connect(Request $request)
    {
        try {
            $res = Http::timeout(5)->get("{$this->baseUrl}/api/status");
            if ($res->successful()) {
                return response()->json(['ok' => true, 'status' => 'reachable']);
            }
            return response()->json(['ok' => false, 'status' => 'unreachable'], 503);
        } catch (\Exception $e) {
            Log::warning('[VulnSightBridge] connect failed: ' . $e->getMessage());
            return response()->json(['ok' => false, 'status' => 'unreachable'], 503);
        }
    }

    // POST /api/vapt/ensure-vulnsight-user
    public function ensureUser(Request $request)
    {
        $email = $request->input('email');
        $name = $request->input('name', 'User');

        if (!$email) {
            return response()->json(['error' => 'No email provided'], 422);
        }

        try {
            // Check if user already exists
            $checkRes = Http::timeout(10)
                ->withHeaders(['X-Bridge-Secret' => $this->bridgeSecret])
                ->get("{$this->baseUrl}/bridge/user-exists", ['email' => $email]);

            if ($checkRes->json('exists')) {
                return response()->json(['ok' => true, 'status' => 'exists']);
            }

            // Create user in VulnSight
            Http::timeout(10)
                ->withHeaders(['X-Bridge-Secret' => $this->bridgeSecret])
                ->asJson()
                ->post("{$this->baseUrl}/bridge/create-user", [
                    'name' => $name,
                    'email' => $email,
                    'password' => $this->bridgeSecret,
                ]);

            return response()->json(['ok' => true, 'status' => 'created']);

        } catch (\Exception $e) {
            Log::warning('[VulnSightBridge] ensureUser failed: ' . $e->getMessage());
            return response()->json(['ok' => false], 503);
        }
    }

    // GET /api/vapt/vulnsight-admin-stats
    public function adminStats(Request $request)
    {
        try {
            $loginRes = Http::timeout(10)
                ->asJson()
                ->post("{$this->baseUrl}/api/login", [
                    'email' => env('VULNSIGHT_ADMIN_EMAIL'),
                    'password' => env('VULNSIGHT_ADMIN_PASSWORD'),
                ]);

            if (!$loginRes->successful()) {
                return response()->json(['error' => 'VulnSight auth failed'], 502);
            }

            $cookie = $loginRes->header('Set-Cookie') ?? '';

            $statsRes = Http::timeout(10)
                ->withHeaders(['Cookie' => $cookie])
                ->get("{$this->baseUrl}/api/admin/stats");

            if ($statsRes->successful()) {
                return response()->json($statsRes->json());
            }

            return response()->json(['error' => 'Stats fetch failed'], 502);

        } catch (\Exception $e) {
            Log::warning('[VulnSightBridge] adminStats failed: ' . $e->getMessage());
            return response()->json(['error' => 'VulnSight unreachable'], 503);
        }
    }

    // GET /api/vapt/vulnsight-health
    public function health()
    {
        try {
            $start = microtime(true);
            $res = Http::timeout(5)->get("{$this->baseUrl}/api/status");
            $ms = round((microtime(true) - $start) * 1000);

            return response()->json([
                'name' => 'VulnSight Scanner',
                'status' => $res->successful() ? 'operational' : 'degraded',
                'latency' => "{$ms}ms",
                'url' => $this->baseUrl,
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'name' => 'VulnSight Scanner',
                'status' => 'down',
                'latency' => '—',
                'url' => $this->baseUrl,
            ]);
        }
    }
}
