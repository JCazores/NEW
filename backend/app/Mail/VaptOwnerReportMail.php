<?php

namespace App\Mail;

use App\Models\VaptScan;
use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Attachment;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Collection;

class VaptOwnerReportMail extends Mailable
{
    use Queueable, SerializesModels;

    public function __construct(
        public VaptScan   $scan,
        public Collection $vulns,
        public string     $pdfPath,
    ) {}

    public function envelope(): Envelope
    {
        $total   = $this->vulns->count();
        $subject = $total > 0
            ? "⚠️ Network Vulnerability Report — {$this->scan->target} ({$total} finding" . ($total !== 1 ? 's' : '') . ' found)'
            : "✅ Network Vulnerability Report — {$this->scan->target} (No vulnerabilities detected)";

        return new Envelope(subject: $subject);
    }

    public function content(): Content
    {
        return new Content(
            view: 'emails.vapt-owner-report',
            with: [
                'scan'  => $this->scan,
                'vulns' => $this->vulns,
            ],
        );
    }

    public function attachments(): array
    {
        $filename = 'VAPT-Report-'
            . str_replace(['/', '\\', ' ', '.'], '-', $this->scan->target)
            . '-' . $this->scan->created_at->format('Y-m-d') . '.pdf';

        return [
            Attachment::fromPath($this->pdfPath)
                ->as($filename)
                ->withMime('application/pdf'),
        ];
    }
}