<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->enum('status', ['pending', 'registered', 'active', 'disabled'])->default('pending')->after('role');
            $table->boolean('is_online')->default(false)->after('status');
            $table->timestamp('last_seen_at')->nullable()->after('is_online');
        });
        
        // Drop old is_active column if it exists
        if (Schema::hasColumn('users', 'is_active')) {
            Schema::table('users', function (Blueprint $table) {
                $table->dropColumn('is_active');
            });
        }
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->boolean('is_active')->default(false);
            $table->dropColumn(['status', 'is_online', 'last_seen_at']);
        });
    }
};