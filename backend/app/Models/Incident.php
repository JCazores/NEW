<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Incident extends Model
{
    protected $fillable = [
        'monitor_id',
        'started_at',
        'resolved_at',
        'status',
        'reason',
        'root_cause',
        'error_type',
        'error_message',
        'http_status_code',
        'down_duration_seconds',
    ];

    protected $casts = [
        'started_at' => 'datetime',
        'resolved_at' => 'datetime',
    ];

    public function monitor(): BelongsTo
    {
        return $this->belongsTo(Monitor::class);
    }

    public function calculateDuration()
    {
        if ($this->resolved_at) {
            $this->down_duration_seconds = $this->started_at->diffInSeconds($this->resolved_at);
            $this->save();
        }
    }
}