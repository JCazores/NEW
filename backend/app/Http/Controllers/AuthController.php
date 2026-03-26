<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Services\OtpService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    private const MAX_ATTEMPTS = 5;
    private const LOCKOUT_SECONDS = 300; // 5 minutes

    public function __construct(private OtpService $otpService) {}

    private function createToken(User $user): string
    {
        return $user->createToken('auth-token', ['*'], now()->addMinutes(480))->plainTextToken;
    }

    // Throttle key per email + IP
    private function throttleKey(Request $request): string
    {
        return 'login:' . strtolower($request->input('email')) . '|' . $request->ip();
    }

    private function checkRateLimit(Request $request)
    {
        $key      = $this->throttleKey($request);
        $attempts = RateLimiter::attempts($key);

        if (RateLimiter::tooManyAttempts($key, self::MAX_ATTEMPTS)) {
            $seconds = RateLimiter::availableIn($key);
            $minutes = ceil($seconds / 60);
            return response()->json([
                'message'          => "Too many failed attempts. Try again in {$minutes} minute(s).",
                'locked_out'       => true,
                'available_in'     => $seconds,
                'attempts_left'    => 0,
            ], 429);
        }

        return null; // not locked out
    }

    private function failAttempt(Request $request): array
    {
        $key  = $this->throttleKey($request);
        RateLimiter::hit($key, self::LOCKOUT_SECONDS);
        $left = self::MAX_ATTEMPTS - RateLimiter::attempts($key);

        return [
            'attempts_left' => max(0, $left),
            'locked_out'    => $left <= 0,
        ];
    }

    private function clearAttempts(Request $request): void
    {
        RateLimiter::clear($this->throttleKey($request));
    }

    public function login(Request $request)
    {
        $data = $request->validate([
            'email'    => 'required|email',
            'password' => 'nullable|string',
        ]);

        // ── Rate limit check ───────────────────────────────────────────────
        if ($response = $this->checkRateLimit($request)) {
            return $response;
        }

        $user = User::where('email', $data['email'])->first();

        if (!$user) {
            $info = $this->failAttempt($request);
            return response()->json([
                'message'       => 'Email not found. Please contact administrator.',
                'attempts_left' => $info['attempts_left'],
                'locked_out'    => $info['locked_out'],
            ], 404);
        }

        // ── Admin: password login ──────────────────────────────────────────
        if ($user->role === 'admin') {
            if (empty($data['password'])) {
                return response()->json(['message' => 'Password required for admin login.'], 422);
            }

            if (!Hash::check($data['password'], $user->password)) {
                $info = $this->failAttempt($request);
                return response()->json([
                    'message'       => 'Invalid password.',
                    'attempts_left' => $info['attempts_left'],
                    'locked_out'    => $info['locked_out'],
                ], 422);
            }

            $this->clearAttempts($request);
            $user->markOnline();
            return response()->json([
                'user'         => $user,
                'token'        => $this->createToken($user),
                'requires_otp' => false,
            ]);
        }

        // ── Regular user: disabled check ───────────────────────────────────
        if ($user->status === 'disabled') {
            return response()->json(['message' => 'Your account has been disabled.'], 403);
        }

        // ── Pending: first-time OTP ────────────────────────────────────────
        if ($user->status === 'pending') {
            $this->clearAttempts($request);
            $otp = $this->otpService->generate($user);
            $this->otpService->send($user, $otp);
            return response()->json([
                'message'      => 'OTP sent to your email. Complete your registration.',
                'requires_otp' => true,
                'email'        => $user->email,
            ]);
        }

        // ── Registered/active with password ───────────────────────────────
        if (in_array($user->status, ['registered', 'active']) && $user->password) {
            if (empty($data['password'])) {
                return response()->json(['message' => 'Password required.'], 422);
            }

            if (!Hash::check($data['password'], $user->password)) {
                $info = $this->failAttempt($request);
                return response()->json([
                    'message'       => 'Invalid password.',
                    'attempts_left' => $info['attempts_left'],
                    'locked_out'    => $info['locked_out'],
                ], 422);
            }

            $this->clearAttempts($request);
            $user->markOnline();
            return response()->json([
                'user'         => $user,
                'token'        => $this->createToken($user),
                'requires_otp' => false,
            ]);
        }

        // ── Fallback: OTP ──────────────────────────────────────────────────
        $this->clearAttempts($request);
        $otp = $this->otpService->generate($user);
        $this->otpService->send($user, $otp);
        return response()->json([
            'message'      => 'OTP sent to your email.',
            'requires_otp' => true,
            'email'        => $user->email,
        ]);
    }

    public function verifyOtp(Request $request)
    {
        $data = $request->validate([
            'email'                 => 'required|email',
            'otp'                   => 'required|string|size:6',
            'name'                  => 'required|string|max:100',
            'password'              => 'required|string|min:8',
            'password_confirmation' => 'required|same:password',
        ]);

        $user   = User::where('email', $data['email'])->firstOrFail();
        $result = $this->otpService->verify($user, $data['otp']);

        if (!$result['success']) {
            return response()->json(['message' => $result['message']], 422);
        }

        $user->update([
            'name'              => $data['name'],
            'password'          => Hash::make($data['password']),
            'status'            => 'registered',
            'email_verified_at' => now(),
        ]);

        $user->markOnline();
        return response()->json([
            'user'    => $user,
            'token'   => $this->createToken($user),
            'message' => 'Account setup complete!',
        ]);
    }

    public function resendOtp(Request $request)
    {
        $data = $request->validate(['email' => 'required|email']);
        $user = User::where('email', $data['email'])->firstOrFail();
        $otp  = $this->otpService->generate($user);
        $this->otpService->send($user, $otp);
        return response()->json(['message' => 'OTP resent successfully.']);
    }

    public function logout(Request $request)
    {
        $request->user()->markOffline();
        $request->user()->currentAccessToken()->delete();
        return response()->json(['message' => 'Logged out successfully.']);
    }

    public function me(Request $request)
    {
        return response()->json($request->user()->load('monitors'));
    }
}