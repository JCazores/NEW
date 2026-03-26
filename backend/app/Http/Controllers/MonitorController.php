<?php

namespace App\Http\Controllers;

use App\Models\Monitor;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class MonitorController extends Controller
{
    public function index()
    {
        $monitors = Monitor::with(['user', 'recipients'])
            ->orderBy('created_at', 'desc')
            ->get();

        return response()->json([
            'success' => true,
            'data' => $monitors
        ]);
    }

    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'user_id'           => 'required|exists:users,id',
            'name'              => 'required|string|max:255',
            'url'               => 'required|url',
            'category'          => 'nullable|in:Military,Schools,Government,Municipality,Others', // ← NEW
            'check_ssl'         => 'boolean',
            'additional_emails' => 'nullable|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'errors'  => $validator->errors()
            ], 422);
        }

        $monitor = Monitor::create([
            'user_id'                => $request->user_id,
            'name'                   => $request->name,
            'url'                    => $request->url,
            'category'               => $request->category ?? 'Others', // ← NEW
            'check_ssl'              => $request->check_ssl ?? true,
            'check_interval_seconds' => 2,
            'is_active'              => true,
        ]);

        // Add additional email recipients if provided
        if ($request->additional_emails) {
            $emails = array_map('trim', explode(',', $request->additional_emails));
            foreach ($emails as $email) {
                if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
                    $monitor->recipients()->create(['email' => $email]);
                }
            }
        }

        return response()->json([
            'success' => true,
            'message' => 'Monitor created successfully',
            'data'    => $monitor->load(['user', 'recipients'])
        ], 201);
    }

    public function update(Request $request, Monitor $monitor)
    {
        $validator = Validator::make($request->all(), [
            'name'     => 'sometimes|string|max:255',
            'url'      => 'sometimes|url',
            'category' => 'sometimes|in:Military,Schools,Government,Municipality,Others', // ← NEW
            'check_ssl'=> 'sometimes|boolean',
            'is_active'=> 'sometimes|boolean',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'errors'  => $validator->errors()
            ], 422);
        }

        $monitor->update($request->only(['name', 'url', 'category', 'check_ssl', 'is_active'])); // ← added category

        return response()->json([
            'success' => true,
            'message' => 'Monitor updated successfully',
            'data'    => $monitor->load(['user', 'recipients'])
        ]);
    }

    public function destroy(Monitor $monitor)
    {
        $monitor->delete();

        return response()->json([
            'success' => true,
            'message' => 'Monitor deleted successfully'
        ]);
    }

    public function toggle(Monitor $monitor)
    {
        $monitor->update([
            'is_active' => !$monitor->is_active
        ]);

        return response()->json([
            'success' => true,
            'message' => 'Monitor ' . ($monitor->is_active ? 'activated' : 'paused') . ' successfully',
            'data'    => $monitor->load(['user', 'recipients'])
        ]);
    }

    public function getUsers()
    {
        $users = User::where('role', 'user')
            ->where('is_verified', true)
            ->select('id', 'name', 'email')
            ->get();

        return response()->json([
            'success' => true,
            'data'    => $users
        ]);
    }
}