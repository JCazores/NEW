<?php

namespace App\Mail;

use App\Models\Monitor;
use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;

class SslExpiryWarning extends Mailable
{
    use Queueable, SerializesModels;

    public function __construct(
        public Monitor $monitor,
        public int $daysRemaining
    ) {}

    public function build()
    {
        $status = $this->daysRemaining <= 0 ? 'EXPIRED' : 'EXPIRING SOON';
        
        return $this->subject("🔒 SSL Certificate {$status} - {$this->monitor->name}")
                    ->markdown('emails.ssl-expiry');
    }
}