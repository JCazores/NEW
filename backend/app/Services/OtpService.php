<?php

namespace App\Services;

use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use App\Mail\OtpMail;
use Carbon\Carbon;

class OtpService
{
    const EXPIRY_MINUTES = 10;

    public function generate(User $user): string
    {
        $otp = (string) random_int(100000, 999999);
        
        $user->update([
            'otp_code' => Hash::make($otp),
            'otp_expires_at' => Carbon::now()->addMinutes(self::EXPIRY_MINUTES),
        ]);

        return $otp;
    }

    public function send(User $user, string $otp): void
    {
        Mail::to($user->email)->send(new OtpMail($user, $otp));
    }

    public function verify(User $user, string $plainOtp): array
    {
        if (!$user->otp_code) {
            return ['success' => false, 'message' => 'No OTP found. Please request a new one.'];
        }

        if (Carbon::now()->isAfter($user->otp_expires_at)) {
            return ['success' => false, 'message' => 'OTP has expired. Please request a new one.'];
        }

        if (!Hash::check($plainOtp, $user->otp_code)) {
            return ['success' => false, 'message' => 'Invalid OTP.'];
        }

        $user->update([
            'otp_code' => null,
            'otp_expires_at' => null,
            'email_verified_at' => now(),
            'is_active' => true,
        ]);

        return ['success' => true];
    }
}