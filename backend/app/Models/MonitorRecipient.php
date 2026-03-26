<?php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class MonitorRecipient extends Model
{
    protected $fillable = ['monitor_id', 'email'];

    public function monitor()
    {
        return $this->belongsTo(Monitor::class);
    }
}
