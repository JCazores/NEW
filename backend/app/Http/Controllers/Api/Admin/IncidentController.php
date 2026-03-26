<?php

namespace App\Http\Controllers\Api\Admin;

use App\Http\Controllers\Controller;
use App\Models\Incident;
use Illuminate\Http\Request;

class IncidentController extends Controller
{
    /**
     * Return ALL incidents — open and resolved — newest first.
     * Resolved incidents are NEVER deleted; they stay in history permanently.
     */
    public function index(Request $request)
    {
        $query = Incident::with(['monitor.user'])
            ->orderBy('started_at', 'desc');

        // Optional status filter from query param (open / resolved)
        if ($request->filled('status') && in_array($request->status, ['open', 'resolved'])) {
            $query->where('status', $request->status);
        }

        $incidents = $query->get();

        return response()->json([
            'data' => $incidents,
        ]);
    }

    /**
     * Basic stats for dashboard/charts.
     */
    public function stats()
    {
        $total    = Incident::count();
        $open     = Incident::where('status', 'open')->count();
        $resolved = Incident::where('status', 'resolved')->count();

        $avgDuration = Incident::where('status', 'resolved')
            ->whereNotNull('down_duration_seconds')
            ->avg('down_duration_seconds');

        return response()->json([
            'total'        => $total,
            'open'         => $open,
            'resolved'     => $resolved,
            'avg_duration' => $avgDuration ? round($avgDuration) : null,
        ]);
    }

    /**
     * Update the root_cause field for a specific incident.
     * Admin only.
     */
    public function updateRootCause(Request $request, Incident $incident)
    {
        $request->validate([
            'root_cause' => 'nullable|string|max:1000',
        ]);

        $incident->update([
            'root_cause' => $request->input('root_cause'),
        ]);

        return response()->json([
            'message'    => 'Root cause updated.',
            'incident'   => $incident->fresh(['monitor.user']),
        ]);
    }
}