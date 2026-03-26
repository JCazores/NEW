@component('mail::message')
# ✅ Monitor Resolved: Server UP

Your monitored server **{{ $monitor->name }}** is back **UP** and running normally.

## Details

- **Monitor Name:** {{ $monitor->name }}
- **URL:** {{ $monitor->url }}
- **Status:** UP ✅
- **Resolved At:** {{ now()->format('F d, Y H:i:s') }}

@if($monitor->last_response_time_ms)
- **Response Time:** {{ $monitor->last_response_time_ms }}ms
@endif

The issue has been resolved and your server is operational again.

@component('mail::button', ['url' => config('app.frontend_url', 'http://localhost:5173') . '/user/monitors'])
View Monitor
@endcomponent

Thanks,<br>
**{{ config('app.name') }}**
@endcomponent