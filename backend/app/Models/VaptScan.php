<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class VaptScan extends Model
{
    protected $fillable = [
        'user_id',
        'type',
        'target',
        'owner_name',   // network owner name (for email report delivery)
        'owner_email',  // network owner email (admin must approve before sending)
        'scan_type',
        'status',
        'phase',
        'progress',
        'phase_log',
        'error_message',
    ];

    protected $casts = [
        'phase_log' => 'array',
        'progress'  => 'integer',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function vulnerabilities(): HasMany
    {
        return $this->hasMany(VaptVulnerability::class, 'scan_id');
    }
}