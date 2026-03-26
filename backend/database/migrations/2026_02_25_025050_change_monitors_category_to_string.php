<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Convert ENUM to VARCHAR so custom categories work
        DB::statement("ALTER TABLE monitors MODIFY category VARCHAR(50) NOT NULL DEFAULT 'Others'");
    }

    public function down(): void
    {
        // Roll back to ENUM (original values)
        DB::statement("
            ALTER TABLE monitors
            MODIFY category ENUM('Military','Schools','Government','Municipality','Others')
            NOT NULL DEFAULT 'Others'
        ");
    }
};