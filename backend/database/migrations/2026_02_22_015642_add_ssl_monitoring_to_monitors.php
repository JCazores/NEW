<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('monitors', function (Blueprint $table) {
            $table->boolean('check_ssl')->default(true)->after('check_interval_seconds');
            $table->timestamp('ssl_expires_at')->nullable()->after('check_ssl');
            $table->string('ssl_issuer')->nullable()->after('ssl_expires_at');
            $table->integer('ssl_days_remaining')->nullable()->after('ssl_issuer');
            $table->timestamp('ssl_last_checked_at')->nullable()->after('ssl_days_remaining');
        });
    }

    public function down(): void
    {
        Schema::table('monitors', function (Blueprint $table) {
            $table->dropColumn([
                'check_ssl',
                'ssl_expires_at',
                'ssl_issuer',
                'ssl_days_remaining',
                'ssl_last_checked_at',
            ]);
        });
    }
};