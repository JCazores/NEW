@component('mail::message')
# Welcome to UpTimeBot, {{ $user->name }}!

Your administrator has created an account for you. Please verify your email address by entering this code:

@component('mail::panel')
# {{ $otp }}
@endcomponent

This code expires in **10 minutes**. Do not share it with anyone.

If you did not expect this email, please contact your administrator.

Thanks,<br>
**UpTimeBot Team**
@endcomponent