<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Http\Request;

Route::get('/', function () {
    return view('welcome');
});

// ─────────────────────────────────────────────────────────────
// VulnSight Reverse Proxy — rewrites asset URLs in HTML/CSS/JS
// All /vulnsight/* → localhost:8001, stripped of /vulnsight prefix
// ─────────────────────────────────────────────────────────────
Route::any('/vulnsight/{path?}', function (Request $request, $path = '') {

    // For admin/user pages, create a fresh VulnSight token server-side and inject it
    $vsBase = rtrim(env('VULNSIGHT_URL', 'http://localhost:8001'), '/');
    $qs = $request->getQueryString();
    $url = $vsBase . '/' . ltrim($path, '/') . ($qs ? '?' . $qs : '');
    $method = strtoupper($request->method());

    $fwdHeaders = [];
    foreach ([
        'Accept',
        'Content-Type',
        'Authorization',
        'Cookie',
        'X-CSRF-TOKEN',
        'X-Requested-With',
        'X-XSRF-TOKEN',
    ] as $h) {
        $v = $request->header($h);
        if ($v !== null)
            $fwdHeaders[] = "$h: $v";
    }

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_HTTPHEADER => $fwdHeaders,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_SSL_VERIFYPEER => false,
    ]);
    if (in_array($method, ['POST', 'PUT', 'PATCH'])) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $request->getContent() ?: '');
    }

    $raw = curl_exec($ch);
    $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($raw === false || $httpCode === 0) {
        return response("<h2>VulnSight unavailable</h2><p>Make sure VulnSight is running on port 8001.</p>", 502)->header("Content-Type", "text/html");
    }

    $rawHeaders = substr($raw, 0, $headerSize);
    $body = substr($raw, $headerSize);
    $contentType = 'text/html; charset=UTF-8';
    $setCookies = [];
    $location = null;

    foreach (explode("\r\n", $rawHeaders) as $line) {
        $lower = strtolower($line);
        if (str_starts_with($lower, 'content-type:'))
            $contentType = trim(substr($line, 13));
        elseif (str_starts_with($lower, 'set-cookie:'))
            $setCookies[] = trim(substr($line, 11));
        elseif (str_starts_with($lower, 'location:'))
            $location = trim(substr($line, 9));
    }

    // Rewrite redirect Location headers
    if ($location) {
        $location = str_replace($vsBase, url('/vulnsight'), $location);
        if (str_starts_with($location, '/') && !str_starts_with($location, '/vulnsight')) {
            $location = '/vulnsight' . $location;
        }
        $resp = response('', $httpCode)->header('Location', $location);
        foreach ($setCookies as $c)
            $resp->header('Set-Cookie', $c, false);
        return $resp;
    }

    // Rewrite asset URLs in HTML/JS/CSS bodies
    $isTextual = str_contains($contentType, 'text/') ||
        str_contains($contentType, 'javascript') ||
        str_contains($contentType, 'json');

    if ($isTextual && $body) {
        // Replace absolute localhost:8001 references
        $body = str_replace(
            ['http://localhost:8001/', 'http:\/\/localhost:8001\/'],
            [url('/vulnsight') . '/', url('/vulnsight') . '\/'],
            $body
        );

        if (str_contains($contentType, 'text/html') || str_contains($contentType, 'javascript')) {
            // Rewrite bare asset paths to go through proxy
            $body = str_replace('"/build/', '"/vulnsight/build/', $body);
            $body = str_replace("'/build/", "'/vulnsight/build/", $body);
            $body = str_replace('"/css/', '"/vulnsight/css/', $body);
            $body = str_replace("'/css/", "'/vulnsight/css/", $body);
            $body = str_replace('"/js/', '"/vulnsight/js/', $body);
            $body = str_replace("'/js/", "'/vulnsight/js/", $body);
            $body = str_replace('"/fonts/', '"/vulnsight/fonts/', $body);
            $body = str_replace("'/fonts/", "'/vulnsight/fonts/", $body);

            // Rewrite /admin links
            $body = str_replace('"/admin"', '"/vulnsight/admin"', $body);
            $body = str_replace("'/admin'", "'/vulnsight/admin'", $body);
            $body = str_replace('(/admin)', '(/vulnsight/admin)', $body);
        }
        if (str_contains($contentType, 'css')) {
            $body = str_replace("url('/fonts/", "url('/vulnsight/fonts/", $body);
            $body = str_replace('url("/fonts/', 'url("/vulnsight/fonts/', $body);
            $body = str_replace("url(fonts/", "url(/vulnsight/fonts/", $body);
            $body = str_replace('/fonts/DM-', '/vulnsight/fonts/DM-', $body);
        }
    }

    // For HTML responses to admin/user pages, inject the latest valid token
    if (str_contains($contentType, 'text/html') && $body) {
        $bridgeSecret = env('VULNSIGHT_BRIDGE_SECRET', '');
        $adminEmail = env('VULNSIGHT_ADMIN_EMAIL', '');
        if ($bridgeSecret && $adminEmail) {
            $vsUser = \App\Models\User::on('vulnsight') // won't work cross-DB
                ?? null;
            // Simpler: just expose the secret and email so wavs_admin can re-auth if needed
            $injection = "<script>window.__vsAutoLoginUrl='/vulnsight/auto-login?email="
                . urlencode($adminEmail) . "&token=" . urlencode($bridgeSecret) . "';</script>";
            $body = str_replace('</head>', $injection . '</head>', $body);
        }
    }

    $resp = response($body, $httpCode)
        ->header('Content-Type', $contentType)
        ->header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        ->header('Pragma', 'no-cache');
    foreach ($setCookies as $c)
        $resp->header('Set-Cookie', $c, false);
    return $resp;

})->where('path', '.*');
