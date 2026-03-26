<?php

namespace App\Services;

use Exception;

class SslCheckService
{
    public function checkSslCertificate(string $url): ?array
    {
        try {
            $parsedUrl = parse_url($url);
            $host = $parsedUrl['host'] ?? null;
            
            if (!$host) {
                return null;
            }

            if (($parsedUrl['scheme'] ?? 'http') !== 'https') {
                return null;
            }

            $port = $parsedUrl['port'] ?? 443;

            $context = stream_context_create([
                'ssl' => [
                    'capture_peer_cert' => true,
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                ],
            ]);

            $client = @stream_socket_client(
                "ssl://{$host}:{$port}",
                $errno,
                $errstr,
                30,
                STREAM_CLIENT_CONNECT,
                $context
            );

            if (!$client) {
                return null;
            }

            $params = stream_context_get_params($client);
            fclose($client);

            if (!isset($params['options']['ssl']['peer_certificate'])) {
                return null;
            }

            $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);

            if (!$cert) {
                return null;
            }

            $expiryTimestamp = $cert['validTo_time_t'];
            $expiryDate = date('Y-m-d H:i:s', $expiryTimestamp);
            $issuer = $cert['issuer']['O'] ?? $cert['issuer']['CN'] ?? 'Unknown';
            $daysRemaining = floor(($expiryTimestamp - time()) / 86400);

            return [
                'expires_at' => $expiryDate,
                'issuer' => $issuer,
                'days_remaining' => $daysRemaining,
                'is_valid' => $daysRemaining > 0,
                'checked_at' => now(),
            ];
        } catch (Exception $e) {
            \Log::error('SSL check failed: ' . $e->getMessage());
            return null;
        }
    }

    public function shouldWarnAboutExpiry(int $daysRemaining): bool
    {
        return in_array($daysRemaining, [30, 14, 7, 3, 1]);
    }
}