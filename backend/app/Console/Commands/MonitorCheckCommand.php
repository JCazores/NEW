<?php

namespace App\Console\Commands;

use App\Models\Monitor;
use App\Services\MonitoringService;
use Illuminate\Console\Command;

class MonitorCheckCommand extends Command
{
    protected $signature = 'monitors:check-daemon';
    protected $description = 'Run monitoring checks every 2 seconds as a daemon';

    public function __construct(
        private MonitoringService $monitoringService
    ) {
        parent::__construct();
    }

    public function handle(): void
    {
        $this->info('Starting monitoring daemon (checking every 2 seconds)...');
        
        while (true) {
            $start = microtime(true);
            
            $activeMonitors = Monitor::where('is_active', true)->get();
            
            $this->info('[' . now()->format('Y-m-d H:i:s') . '] Checking ' . $activeMonitors->count() . ' monitors...');
            
            foreach ($activeMonitors as $monitor) {
                try {
                    $this->monitoringService->checkMonitor($monitor);
                    $this->line("  ✓ {$monitor->name} - {$monitor->last_status}");
                } catch (\Exception $e) {
                    $this->error("  ✗ {$monitor->name} - Error: " . $e->getMessage());
                }
            }
            
            $elapsed = microtime(true) - $start;
            $this->info("Check completed in " . round($elapsed, 2) . "s");
            
            // Sleep for 2 seconds minus execution time
            $sleepTime = max(0, 2000000 - (int)($elapsed * 1000000));
            usleep($sleepTime);
        }
    }
}