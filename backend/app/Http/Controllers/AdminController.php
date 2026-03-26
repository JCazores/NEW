<?php

namespace App\Http\Controllers;

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
            'total_users'    => User::where('role', 'user')->count(),
            'active_users'   => User::where('role', 'user')->where('status', 'active')->count(),
            'total_monitors' => Monitor::count(),
            'active_monitors'=> Monitor::where('is_active', true)->count(),
            'monitors_up'    => Monitor::where('last_status', 'up')->count(),
            'monitors_down'  => Monitor::where('last_status', 'down')->count(),
            'open_incidents' => Incident::where('status', 'open')->count(),
            'total_incidents'=> Incident::count(),
        ];

        return response()->json(['success' => true, 'data' => $stats]);
    }

    public function getMonitorStats(Request $request)
    {
        $period = $request->get('period', 'week');
        $query  = Monitor::selectRaw('DATE(created_at) as date, COUNT(*) as count');
        switch ($period) {
            case 'day':   $query->where('created_at', '>=', now()->subDay());   break;
            case 'week':  $query->where('created_at', '>=', now()->subWeek());  break;
            case 'month': $query->where('created_at', '>=', now()->subMonth()); break;
        }
        return response()->json(['success' => true, 'data' => $query->groupBy('date')->orderBy('date')->get()]);
    }

    public function getIncidentStats(Request $request)
    {
        $period = $request->get('period', 'week');
        $query  = Incident::selectRaw('DATE(created_at) as date, COUNT(*) as count');
        switch ($period) {
            case 'day':   $query->where('created_at', '>=', now()->subDay());   break;
            case 'week':  $query->where('created_at', '>=', now()->subWeek());  break;
            case 'month': $query->where('created_at', '>=', now()->subMonth()); break;
        }
        return response()->json(['success' => true, 'data' => $query->groupBy('date')->orderBy('date')->get()]);
    }

    public function getIncidentsByCause(Request $request)
    {
        $period = $request->get('period', 'week');
        $query  = Incident::selectRaw('error_type, COUNT(*) as count');
        switch ($period) {
            case 'hour':  $query->where('created_at', '>=', now()->subHour());  break;
            case 'day':   $query->where('created_at', '>=', now()->subDay());   break;
            case 'week':  $query->where('created_at', '>=', now()->subWeek());  break;
            case 'month': $query->where('created_at', '>=', now()->subMonth()); break;
        }
        return response()->json(['success' => true, 'data' => $query->groupBy('error_type')->orderBy('count', 'desc')->get()]);
    }

    public function getIncidentsByUser(Request $request)
    {
        $period = $request->get('period', 'week');
        $query  = Incident::join('monitors', 'incidents.monitor_id', '=', 'monitors.id')
                          ->join('users', 'monitors.user_id', '=', 'users.id')
                          ->selectRaw('users.name as user_name, users.email, COUNT(incidents.id) as count');
        switch ($period) {
            case 'hour':  $query->where('incidents.created_at', '>=', now()->subHour());  break;
            case 'day':   $query->where('incidents.created_at', '>=', now()->subDay());   break;
            case 'week':  $query->where('incidents.created_at', '>=', now()->subWeek());  break;
            case 'month': $query->where('incidents.created_at', '>=', now()->subMonth()); break;
        }
        return response()->json(['success' => true, 'data' => $query->groupBy('users.id', 'users.name', 'users.email')->orderBy('count', 'desc')->get()]);
    }

    public function exportIncidentsPdf(Request $request)
    {
        $period = $request->get('period', 'week');
        $query  = Incident::with(['monitor.user']);
        switch ($period) {
            case 'hour':  $query->where('created_at', '>=', now()->subHour());  break;
            case 'day':   $query->where('created_at', '>=', now()->subDay());   break;
            case 'week':  $query->where('created_at', '>=', now()->subWeek());  break;
            case 'month': $query->where('created_at', '>=', now()->subMonth()); break;
        }
        return response()->json(['success' => true, 'data' => $query->orderBy('created_at', 'desc')->get()]);
    }

    public function users()
    {
        $users = User::where('role', 'user')
            ->withCount('monitors')
            ->orderBy('created_at', 'desc')
            ->get();

        return response()->json(['success' => true, 'data' => $users]);
    }

    public function createUser(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name'  => 'required|string|max:255',
            'email' => 'required|email|unique:users,email',
        ]);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'errors' => $validator->errors()], 422);
        }

        $user = User::create([
            'name'        => $request->name,
            'email'       => $request->email,
            'role'        => 'user',
            'status'      => 'pending',
            'permissions' => [],
        ]);

        $otp = $this->otpService->generate($user);
        $this->otpService->send($user, $otp);

        return response()->json(['success' => true, 'message' => 'User created and OTP sent', 'data' => $user], 201);
    }

    public function deleteUser(User $user)
    {
        if ($user->role === 'admin') {
            return response()->json(['success' => false, 'message' => 'Cannot delete admin users'], 403);
        }
        $user->delete();
        return response()->json(['success' => true, 'message' => 'User deleted successfully']);
    }

    public function updateStatus(Request $request, User $user)
    {
        $validator = Validator::make($request->all(), [
            'status' => 'required|in:active,disabled'
        ]);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'errors' => $validator->errors()], 422);
        }

        $user->update(['status' => $request->status]);
        return response()->json(['success' => true, 'message' => 'User status updated', 'data' => $user]);
    }

    // ─── NEW: Update user permissions ────────────────────────────────────────────
    public function updatePermissions(Request $request, User $user)
    {
        if ($user->role === 'admin') {
            return response()->json(['success' => false, 'message' => 'Cannot modify admin permissions'], 403);
        }

        $validator = Validator::make($request->all(), [
            'permissions'   => 'present|array',
            'permissions.*' => 'in:monitors,vapt',
        ]);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'errors' => $validator->errors()], 422);
        }

        $user->update(['permissions' => $request->permissions]);

        return response()->json([
            'success' => true,
            'message' => 'Permissions updated',
            'data'    => $user,
        ]);
    }

    public function resendOtp(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email|exists:users,email'
        ]);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'errors' => $validator->errors()], 422);
        }

        $user = User::where('email', $request->email)->first();
        $otp  = $this->otpService->generate($user);
        $this->otpService->send($user, $otp);

        return response()->json(['success' => true, 'message' => 'OTP resent successfully']);
    }
}