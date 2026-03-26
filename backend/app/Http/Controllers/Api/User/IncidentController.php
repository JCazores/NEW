<?php

namespace App\Http\Controllers\Api\User;

use App\Http\Controllers\Controller;
use App\Models\Incident;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class IncidentController extends Controller
{
    /**
     * Return ALL incidents for the authenticated user's monitors —
     * open and resolved — newest first. Resolved incidents are never hidden.
     */
    public function index(Request $request)
    {
        $user = Auth::user();

        $query = Incident::with(['monitor'])
            ->whereHas('monitor', fn($q) => $q->where('user_id', $user->id))
            ->orderBy('started_at', 'desc');

        // Optional: filter by monitor_id via ?monitor=X
        if ($request->filled('monitor')) {
            $query->whereHas('monitor', fn($q) =>
                $q->where('id', $request->monitor)->where('user_id', $user->id)
            );
        }

        // Optional: filter by status via ?status=open|resolved
        if ($request->filled('status') && in_array($request->status, ['open', 'resolved'])) {
            $query->where('status', $request->status);
        }

        // Support pagination or return all (default large set)
        $perPage = $request->input('per_page', 200);
        $incidents = $query->limit($perPage)->get();

        return response()->json([
            'data' => $incidents,
        ]);
    }
}