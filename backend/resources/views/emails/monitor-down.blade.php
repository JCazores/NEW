@component('mail::message')
# 🚨 Monitor Alert: Server DOWN

Your monitored server **{{ $monitor->name }}** is currently **DOWN**.

## Details

- **Monitor Name:** {{ $monitor->name }}
- **URL:** {{ $monitor->url }}
- **Status:** DOWN ⚠️
- **Detected At:** {{ now()->format('F d, Y H:i:s') }}

@if($monitor->last_response_time_ms)
- **Last Response Time:** {{ $monitor->last_response_time_ms }}ms
@endif

⚠️ **Action Required:** Please check your server immediately.

@component('mail::button', ['url' => config('app.frontend_url', 'http://localhost:5173') . '/user/monitors'])
View Monitor
@endcomponent

Thanks,<br>
**{{ config('app.name') }}**
@endcomponent