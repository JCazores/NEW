<?php

namespace App\Http\Controllers\Api\User;

use App\Http\Controllers\Controller;
use App\Models\Monitor;
use App\Models\MonitorRecipient;
use Illuminate\Http\Request;

class MonitorController extends Controller
{
    public function index(Request $request)
{
    $monitors = $request->user()
        ->monitors()
        ->with(['latestIncident' => function($query) {
            $query->where('status', 'open')->latest();
        }])
        ->withCount('incidents')
        ->orderBy('created_at', 'desc')
        ->get();

    // Append latest_incident to each monitor
    $monitors->each(function($monitor) {
        $monitor->latest_incident = $monitor->latestIncident;
        unset($monitor->latestIncident);
    });

    return response()->json([
        'success' => true,
        'data' => $monitors
    ]);
}

    public function store(Request $request)
    {
        $data = $request->validate([
            'name' => 'required|string|max:255',
            'url' => 'required|url|max:500',
            'check_interval_seconds' => 'nullable|integer|min:1',
            'recipient_emails' => 'nullable|array',
            'recipient_emails.*' => 'email',
        ]);

        $monitor = Monitor::create([
            'user_id' => $request->user()->id,
            'name' => $data['name'],
            'url' => $data['url'],
            'check_interval_seconds' => $data['check_interval_seconds'] ?? 2,
            'is_active' => true,
        ]);

        if (!empty($data['recipient_emails'])) {
            foreach ($data['recipient_emails'] as $email) {
                MonitorRecipient::create([
                    'monitor_id' => $monitor->id,
                    'email' => $email,
                ]);
            }
        }

        return response()->json([
            'message' => 'Monitor created successfully',
            'data' => $monitor->load('recipients'),
        ], 201);
    }

    public function destroy(Request $request, Monitor $monitor)
    {
        // Security: user can delete only own monitor
        if ($monitor->user_id !== $request->user()->id) {
            return response()->json(['message' => 'Forbidden'], 403);
        }

        $monitor->delete();
        return response()->json(['message' => 'Monitor deleted successfully']);
    }
}