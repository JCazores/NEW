<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Monitor extends Model
{
    protected $fillable = [
        'user_id',
        'name',
        'url',
        'category',                  // ← NEW

        'check_interval_seconds',
        'check_ssl',

        'is_active',
        'last_status',
        'last_checked_at',
        'last_response_time_ms',
        'last_http_code',
        'uptime_percentage',

        // SSL fields (so updates work)
        'ssl_expires_at',
        'ssl_issuer',
        'ssl_days_remaining',
        'ssl_last_checked_at',
    ];

    protected $casts = [
        'is_active'           => 'boolean',
        'check_ssl'           => 'boolean',

        'last_checked_at'     => 'datetime',
        'ssl_expires_at'      => 'datetime',
        'ssl_last_checked_at' => 'datetime',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function recipients(): HasMany
    {
        return $this->hasMany(\App\Models\MonitorRecipient::class);
    }

    public function incidents(): HasMany
    {
        return $this->hasMany(Incident::class);
    }

    public function openIncident()
    {
        return $this->incidents()->where('status', 'open')->latest()->first();
    }

    public function latestIncident()
    {
        return $this->hasOne(Incident::class)->latestOfMany();
    }
}