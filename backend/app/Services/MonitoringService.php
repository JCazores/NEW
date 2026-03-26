<?php

namespace App\Services;

use App\Models\Monitor;
use App\Models\Incident;
use App\Mail\MonitorDown;
use App\Mail\MonitorUp;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Log;

class MonitoringService
{
    private $sslCheckService;

    public function __construct()
    {
        try {
            $this->sslCheckService = new SslCheckService();
        } catch (\Exception $e) {
            Log::error('Failed to init SSL service: ' . $e->getMessage());
            $this->sslCheckService = null;
        }
    }

    public function checkMonitor(Monitor $monitor): void
    {
        $startTime = microtime(true);
        $previousStatus = $monitor->last_status;

        $reason = null;

        try {
            $response = Http::timeout(10)->get($monitor->url);
            $responseTime = (int) round((microtime(true) - $startTime) * 1000);

            $isUp = $response->successful();

            if (!$isUp) {
                $reason = 'HTTP ' . $response->status();
            }

            $monitor->update([
                'last_status' => $isUp ? 'up' : 'down',
                'last_checked_at' => now(),
                'last_response_time_ms' => $responseTime,
            ]);

            if ($this->sslCheckService && $monitor->check_ssl && str_starts_with($monitor->url, 'https://')) {
                $this->checkSsl($monitor);
            }

            // Only act on status change
            if ($isUp && $previousStatus === 'down') {
                $this->handleMonitorUp($monitor);
            } elseif (!$isUp && $previousStatus === 'up') {
                $this->handleMonitorDown($monitor, $reason);
            }
        } catch (\Exception $e) {
            $reason = $e->getMessage();

            $monitor->update([
                'last_status' => 'down',
                'last_checked_at' => now(),
            ]);

            if ($previousStatus === 'up') {
                $this->handleMonitorDown($monitor, $reason);
            }
        }

        $this->updateUptime($monitor);
    }

    private function checkSsl(Monitor $monitor): void
    {
        Log::info("🔒 Checking SSL for: {$monitor->url}");

        if (!$this->sslCheckService) {
            Log::error("SSL service not initialized!");
            return;
        }

        $sslData = $this->sslCheckService->checkSslCertificate($monitor->url);

        if ($sslData) {
            $monitor->update([
                'ssl_expires_at' => $sslData['expires_at'],
                'ssl_issuer' => $sslData['issuer'],
                'ssl_days_remaining' => $sslData['days_remaining'],
                'ssl_last_checked_at' => $sslData['checked_at'],
            ]);

            Log::info("✅ SSL data saved for {$monitor->name}");
        } else {
            Log::warning("SSL check returned NULL for {$monitor->url}");
        }
    }

    private function handleMonitorDown(Monitor $monitor, ?string $reason = null): void
    {
        // Find if there is already an open incident (so we don't spam create)
        $existingOpen = Incident::where('monitor_id', $monitor->id)
            ->where('status', 'open')
            ->orderByDesc('started_at')
            ->first();

        if (!$existingOpen) {
            // Map reason to error_type
            $errorType = 'unknown';
            if ($reason) {
                $lower = strtolower($reason);

                if (str_contains($lower, 'timed out') || str_contains($lower, 'timeout')) {
                    $errorType = 'timeout';
                } elseif (str_contains($lower, 'connection refused') || str_contains($lower, 'connection')) {
                    $errorType = 'connection';
                } elseif (str_contains($lower, 'dns') || str_contains($lower, 'could not resolve')) {
                    $errorType = 'dns';
                } elseif (str_contains($lower, 'ssl')) {
                    $errorType = 'ssl';
                } elseif (str_starts_with($reason, 'HTTP ')) {
                    $errorType = 'http_error';
                }
            }

            // ✅ FIX: include user_id so user reports can fetch it
            Incident::create([
                'monitor_id' => $monitor->id,
                'user_id' => $monitor->user_id,     // ✅ IMPORTANT
                'started_at' => now(),
                'status' => 'open',
                'error_type' => $errorType,
                'error_message' => $reason,
                // 'http_status_code' => optional if you store it separately
            ]);
        }

        // Send emails
        try {
            Mail::to($monitor->user->email)->send(new MonitorDown($monitor));

            foreach ($monitor->recipients as $recipient) {
                Mail::to($recipient->email)->send(new MonitorDown($monitor));
            }

            Log::info("📧 DOWN emails sent for {$monitor->name} | reason={$reason}");
        } catch (\Exception $e) {
            Log::error('Failed to send down notification: ' . $e->getMessage());
        }
    }

    private function handleMonitorUp(Monitor $monitor): void
    {
        // Resolve the open incident
        $incident = Incident::where('monitor_id', $monitor->id)
            ->where('status', 'open')
            ->orderByDesc('started_at')
            ->first();

        if ($incident) {
            $downDuration = now()->diffInSeconds($incident->started_at);

            $incident->update([
                'resolved_at' => now(),
                'status' => 'resolved',
                'down_duration_seconds' => $downDuration, // make sure this column exists in DB
            ]);
        }

        // Send email
        try {
            Mail::to($monitor->user->email)->send(new MonitorUp($monitor));

            foreach ($monitor->recipients as $recipient) {
                Mail::to($recipient->email)->send(new MonitorUp($monitor));
            }

            Log::info("📧 UP emails sent for {$monitor->name}");
        } catch (\Exception $e) {
            Log::error('Failed to send up notification: ' . $e->getMessage());
        }
    }

    private function updateUptime(Monitor $monitor): void
    {
        $totalChecks = Incident::where('monitor_id', $monitor->id)->count() + 1;
        $downChecks = Incident::where('monitor_id', $monitor->id)
            ->where('status', 'resolved')
            ->count();

        $uptime = $totalChecks > 0
            ? round((($totalChecks - $downChecks) / $totalChecks) * 100, 2)
            : 100;

        $monitor->update(['uptime_percentage' => $uptime]);
    }
}