@component('mail::message')
# 🔒 SSL Certificate Warning

@if($daysRemaining <= 0)
**CRITICAL:** The SSL certificate for **{{ $monitor->name }}** has **EXPIRED**.
@elseif($daysRemaining <= 3)
**URGENT:** The SSL certificate for **{{ $monitor->name }}** expires in **{{ $daysRemaining }} day(s)**.
@else
The SSL certificate for **{{ $monitor->name }}** expires in **{{ $daysRemaining }} day(s)**.
@endif

## Certificate Details

- **URL:** {{ $monitor->url }}
- **Issuer:** {{ $monitor->ssl_issuer }}
- **Expires:** {{ \Carbon\Carbon::parse($monitor->ssl_expires_at)->format('F d, Y H:i') }}
- **Days Remaining:** {{ $daysRemaining }}

@if($daysRemaining <= 0)
⚠️ **Action Required:** Your website is currently showing security warnings to visitors. Renew your SSL certificate immediately.
@else
⚠️ **Action Required:** Please renew your SSL certificate as soon as possible to avoid service disruption.
@endif

@component('mail::button', ['url' => config('app.frontend_url', 'http://localhost:5173') . '/user/monitors'])
View Monitor
@endcomponent

Thanks,<br>
**{{ config('app.name') }}**
@endcomponent