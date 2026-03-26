<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable;

    protected $fillable = [
        'name',
        'email',
        'password',
        'role',
        'status',
        'is_online',
        'last_seen_at',
        'otp_code',
        'otp_expires_at',
        'email_verified_at',
        'permissions',
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];

    protected $casts = [
        'email_verified_at' => 'datetime',
        'otp_expires_at'    => 'datetime',
        'last_seen_at'      => 'datetime',
        'password'          => 'hashed',
        'permissions'       => 'array',
    ];

    public function monitors()
    {
        return $this->hasMany(Monitor::class);
    }

    public function isAdmin()
    {
        return $this->role === 'admin';
    }

    public function hasPermission(string $permission): bool
    {
        if ($this->isAdmin()) return true;
        return in_array($permission, $this->permissions ?? []);
    }

    public function markOnline()
    {
        $this->update([
            'is_online'    => true,
            'last_seen_at' => now(),
        ]);
    }

    public function markOffline()
    {
        $this->update(['is_online' => false]);
    }
}