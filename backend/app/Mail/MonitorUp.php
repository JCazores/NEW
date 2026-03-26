<?php

namespace App\Mail;

use App\Models\Monitor;
use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;

class MonitorUp extends Mailable
{
    use Queueable, SerializesModels;

    public $monitor;

    public function __construct(Monitor $monitor)
    {
        $this->monitor = $monitor;
    }

    public function build()
    {
        $name = htmlspecialchars($this->monitor->name);
        $url = htmlspecialchars($this->monitor->url);
        $time = now()->format('F d, Y H:i:s');

        $html = "
        <!DOCTYPE html>
        <html>
        <body style='font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px;'>
            <div style='background: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: 0 auto;'>
                <div style='background: #10b981; color: white; padding: 20px; border-radius: 5px; text-align: center;'>
                    <h1>✅ Server UP</h1>
                </div>
                <div style='padding: 20px;'>
                    <h2>Resolved: {$name}</h2>
                    <p>Your server is back <strong style='color: #10b981;'>UP</strong>.</p>
                    <div style='background: #f9fafb; padding: 15px; border-radius: 5px; margin: 20px 0;'>
                        <p><strong>Monitor:</strong> {$name}</p>
                        <p><strong>URL:</strong> {$url}</p>
                        <p><strong>Status:</strong> UP ✅</p>
                        <p><strong>Time:</strong> {$time}</p>
                    </div>
                    <p>The issue has been resolved.</p>
                    <p><a href='http://localhost:5173/user/monitors' style='background: #10b981; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;'>View Dashboard</a></p>
                </div>
            </div>
        </body>
        </html>
        ";

        return $this->subject("✅ RESOLVED: {$this->monitor->name} is UP")
                    ->html($html);
    }
}