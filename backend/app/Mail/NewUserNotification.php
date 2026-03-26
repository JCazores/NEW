<?php

namespace App\Mail;

use App\Models\User;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;

class NewUserNotification extends Mailable
{
    public function __construct(public User $user) {}

    public function envelope(): Envelope
    {
        return new Envelope(subject: 'New User Registration - UpTimeBot');
    }

    public function content(): Content
    {
        return new Content(
            markdown: 'emails.new-user',
            with: ['user' => $this->user]
        );
    }
}