<?php

namespace App\Http\Controllers\Api\Admin;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Services\OtpService;
use Illuminate\Http\Request;

class UserController extends Controller
{
    public function __construct(private OtpService $otpService) {}

    public function index()
    {
        try {
            $users = User::withCount('monitors')
                ->orderByDesc('created_at')
                ->get();
        } catch (\Exception $e) {
            // Fallback if monitors table not yet migrated
            $users = User::orderByDesc('created_at')->get()
                ->each(fn($u) => $u->monitors_count = 0);
        }

        return response()->json(['data' => $users]);
    }

    public function store(Request $request)
    {
        $data = $request->validate([
            'email' => ['required', 'email', 'unique:users,email', 'regex:/@gmail\.com$/i'],
        ]);

        // Create user with pending status (NO OTP sent yet)
        $user = User::create([
            'name' => explode('@', $data['email'])[0],
            'email' => $data['email'],
            'role' => 'user',
            'status' => 'pending',
        ]);

        // Don't send OTP here - it will be sent when user tries to login

        return response()->json([
            'message' => 'User added successfully. They will receive OTP when they login.',
            'user' => $user,
        ], 201);
    }

    public function destroy(User $user)
    {
        if ($user->role === 'admin') {
            return response()->json(['message' => 'Cannot delete admin user'], 422);
        }

        $user->delete();
        return response()->json(['message' => 'User deleted successfully.']);
    }

    public function updateStatus(User $user, Request $request)
    {
        $data = $request->validate([
            'status' => 'required|in:pending,registered,active,disabled'
        ]);

        if ($user->role === 'admin') {
            return response()->json(['message' => 'Cannot change admin status'], 422);
        }

        $user->update(['status' => $data['status']]);
        return response()->json(['data' => $user]);
    }

    public function resendOtp(Request $request)
    {
        $data = $request->validate(['email' => 'required|email']);

        $user = User::where('email', $data['email'])->firstOrFail();

        $otp = $this->otpService->generate($user);
        $this->otpService->send($user, $otp);

        return response()->json(['message' => 'OTP resent successfully.']);
    }
}
