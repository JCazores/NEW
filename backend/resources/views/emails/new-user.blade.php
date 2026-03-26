@component('mail::message')
# New User Registration

A new user has registered on UpTimeBot:

**Email:** {{ $user->email }}  
**Registered:** {{ $user->created_at->format('Y-m-d H:i:s') }}

The user is currently verifying their email via OTP.

@component('mail::button', ['url' => config('app.frontend_url', 'http://localhost:5173') . '/admin/users'])
View Users
@endcomponent

Thanks,<br>
**UpTimeBot System**
@endcomponent