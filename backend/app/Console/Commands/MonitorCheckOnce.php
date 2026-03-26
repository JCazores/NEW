<?php

namespace App\Console\Commands;

use App\Models\Monitor;
use App\Services\MonitoringService;
use Illuminate\Console\Command;

class MonitorCheckOnce extends Command
{
    protected $signature = 'monitors:check';
    protected $description = 'Check all monitors once (manual trigger)';

    public function __construct(private MonitoringService $monitoringService)
    {
        parent::__construct();
    }

    public function handle(): void
    {
        $activeMonitors = Monitor::where('is_active', true)->get();
        
        $this->info("Checking {$activeMonitors->count()} monitors...");
        
        foreach ($activeMonitors as $monitor) {
            try {
                $this->monitoringService->checkMonitor($monitor);
                $this->line("✓ {$monitor->name} - {$monitor->last_status} ({$monitor->last_response_time_ms}ms)");
            } catch (\Exception $e) {
                $this->error("✗ {$monitor->name} - Error: " . $e->getMessage());
            }
        }
        
        $this->info('Done!');
    }
}