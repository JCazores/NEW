<?php

namespace App\Http\Controllers;

use App\Models\Monitor;
use App\Models\Incident;
use Illuminate\Http\Request;

class UserController extends Controller
{
    public function dashboard(Request $request)
    {
        $user = $request->user();
        
        $stats = [
            'total_monitors' => $user->monitors()->count(),
            'monitors_up' => $user->monitors()->where('last_status', 'up')->count(),
            'monitors_down' => $user->monitors()->where('last_status', 'down')->count(),
            'open_incidents' => Incident::whereHas('monitor', function($q) use ($user) {
                $q->where('user_id', $user->id);
            })->where('status', 'open')->count(),
        ];

        return response()->json([
            'success' => true,
            'data' => $stats
        ]);
    }

    public function getMonitorStats(Request $request)
    {
        $user = $request->user();
        $period = $request->get('period', 'week');
        
        $query = Monitor::where('user_id', $user->id)
                        ->selectRaw('DATE(created_at) as date, COUNT(*) as count');
        
        switch ($period) {
            case 'day':
                $query->where('created_at', '>=', now()->subDay());
                break;
            case 'week':
                $query->where('created_at', '>=', now()->subWeek());
                break;
            case 'month':
                $query->where('created_at', '>=', now()->subMonth());
                break;
        }
        
        $stats = $query->groupBy('date')
                       ->orderBy('date')
                       ->get();
        
        return response()->json([
            'success' => true,
            'data' => $stats
        ]);
    }

    public function getIncidentStats(Request $request)
    {
        $user = $request->user();
        $period = $request->get('period', 'week');
        
        $query = Incident::whereHas('monitor', function($q) use ($user) {
                            $q->where('user_id', $user->id);
                        })
                        ->selectRaw('DATE(created_at) as date, COUNT(*) as count');
        
        switch ($period) {
            case 'day':
                $query->where('created_at', '>=', now()->subDay());
                break;
            case 'week':
                $query->where('created_at', '>=', now()->subWeek());
                break;
            case 'month':
                $query->where('created_at', '>=', now()->subMonth());
                break;
        }
        
        $stats = $query->groupBy('date')
                       ->orderBy('date')
                       ->get();
        
        return response()->json([
            'success' => true,
            'data' => $stats
        ]);
    }

    public function getIncidentsByCause(Request $request)
    {
        $user = $request->user();
        $period = $request->get('period', 'week');
        
        $query = Incident::whereHas('monitor', function($q) use ($user) {
                            $q->where('user_id', $user->id);
                        })
                        ->selectRaw('error_type, COUNT(*) as count');
        
        switch ($period) {
            case 'hour':
                $query->where('created_at', '>=', now()->subHour());
                break;
            case 'day':
                $query->where('created_at', '>=', now()->subDay());
                break;
            case 'week':
                $query->where('created_at', '>=', now()->subWeek());
                break;
            case 'month':
                $query->where('created_at', '>=', now()->subMonth());
                break;
        }
        
        $stats = $query->whereNotNull('error_type')
                       ->groupBy('error_type')
                       ->orderBy('count', 'desc')
                       ->get();
        
        return response()->json([
            'success' => true,
            'data' => $stats
        ]);
    }

    public function exportIncidentsPdf(Request $request)
    {
        $user = $request->user();
        $period = $request->get('period', 'week');
        
        $query = Incident::whereHas('monitor', function($q) use ($user) {
                            $q->where('user_id', $user->id);
                        })
                        ->with('monitor');
        
        switch ($period) {
            case 'hour':
                $query->where('created_at', '>=', now()->subHour());
                break;
            case 'day':
                $query->where('created_at', '>=', now()->subDay());
                break;
            case 'week':
                $query->where('created_at', '>=', now()->subWeek());
                break;
            case 'month':
                $query->where('created_at', '>=', now()->subMonth());
                break;
        }
        
        $incidents = $query->orderBy('created_at', 'desc')->get();
        
        return response()->json([
            'success' => true,
            'data' => $incidents
        ]);
    }

    public function monitors(Request $request)
    {
        $monitors = $request->user()
            ->monitors()
            ->withCount('incidents')
            ->orderBy('created_at', 'desc')
            ->get();

        return response()->json([
            'success' => true,
            'data' => $monitors
        ]);
    }

    public function incidents(Request $request)
    {
        $query = Incident::whereHas('monitor', function($q) use ($request) {
            $q->where('user_id', $request->user()->id);
        })->with('monitor');

        if ($request->has('monitor')) {
            $query->where('monitor_id', $request->monitor);
        }

        $incidents = $query->orderBy('created_at', 'desc')
            ->paginate($request->get('per_page', 20));

        return response()->json([
            'success' => true,
            'data' => $incidents->items(),
            'total' => $incidents->total(),
            'current_page' => $incidents->currentPage(),
            'last_page' => $incidents->lastPage(),
        ]);
    }
}