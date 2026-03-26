<?php

namespace App\Http\Controllers\Api\Admin;

use App\Models\User;
use App\Models\Monitor;
use App\Models\Incident;
use App\Services\OtpService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class AdminController extends Controller
{
    public function __construct(private OtpService $otpService) {}

    public function dashboard()
    {
        $stats = [
            'total_users' => User::where('role', 'user')->count(),
            'active_users' => User::where('role', 'user')->where('status', 'active')->count(),
            'total_monitors' => Monitor::count(),
            'active_monitors' => Monitor::where('is_active', true)->count(),
            'monitors_up' => Monitor::where('last_status', 'up')->count(),
            'monitors_down' => Monitor::where('last_status', 'down')->count(),
            'open_incidents' => Incident::where('status', 'open')->count(),
            'total_incidents' => Incident::count(),
        ];

        return response()->json([
            'success' => true,
            'data' => $stats
        ]);
    }

    public function getMonitorStats(Request $request)
    {
        $period = $request->get('period', 'week');
        
        $query = Monitor::selectRaw('DATE(created_at) as date, COUNT(*) as count');
        
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
        $period = $request->get('period', 'week');
        
        $query = Incident::selectRaw('DATE(created_at) as date, COUNT(*) as count');
        
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

    public function users()
    {
        $users = User::where('role', 'user')
            ->withCount('monitors')
            ->orderBy('created_at', 'desc')
            ->get();

        return response()->json([
            'success' => true,
            'data' => $users
        ]);
    }

    public function createUser(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users,email',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'errors' => $validator->errors()
            ], 422);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'role' => 'user',
            'status' => 'pending',
        ]);

        $otp = $this->otpService->generate($user);
        $this->otpService->send($user, $otp);

        return response()->json([
            'success' => true,
            'message' => 'User created and OTP sent',
            'data' => $user
        ], 201);
    }

    public function deleteUser(User $user)
    {
        if ($user->role === 'admin') {
            return response()->json([
                'success' => false,
                'message' => 'Cannot delete admin users'
            ], 403);
        }

        $user->delete();

        return response()->json([
            'success' => true,
            'message' => 'User deleted successfully'
        ]);
    }

    public function updateStatus(Request $request, User $user)
    {
        $validator = Validator::make($request->all(), [
            'status' => 'required|in:active,disabled'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'errors' => $validator->errors()
            ], 422);
        }

        $user->update(['status' => $request->status]);

        return response()->json([
            'success' => true,
            'message' => 'User status updated',
            'data' => $user
        ]);
    }

    public function resendOtp(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email|exists:users,email'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'errors' => $validator->errors()
            ], 422);
        }

        $user = User::where('email', $request->email)->first();
        
        $otp = $this->otpService->generate($user);
        $this->otpService->send($user, $otp);

        return response()->json([
            'success' => true,
            'message' => 'OTP resent successfully'
        ]);
    }
}