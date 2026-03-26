<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class VaptEmailApproval extends Model
{
    protected $fillable = [
        'scan_id',
        'requested_by',
        'reviewed_by',
        'status',       // pending | approved | rejected
        'admin_note',
        'reviewed_at',
    ];

    protected $casts = [
        'reviewed_at' => 'datetime',
    ];

    public function scan(): BelongsTo
    {
        return $this->belongsTo(VaptScan::class, 'scan_id');
    }

    public function requester(): BelongsTo
    {
        return $this->belongsTo(User::class, 'requested_by');
    }

    public function reviewer(): BelongsTo
    {
        return $this->belongsTo(User::class, 'reviewed_by');
    }
}