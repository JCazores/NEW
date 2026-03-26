<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Adds two things:
 *
 * 1. owner_name + owner_email columns on vapt_scans
 *    — the person who owns the network being scanned (may differ from the user who ran the scan)
 *
 * 2. vapt_email_approvals table
 *    — tracks email-report requests that need admin approval before sending to the owner
 */
return new class extends Migration
{
    public function up(): void
    {
        // ── 1. Owner fields on vapt_scans ────────────────────────────────────
        Schema::table('vapt_scans', function (Blueprint $table) {
            $table->string('owner_name')->nullable()->after('target');
            $table->string('owner_email')->nullable()->after('owner_name');
        });

        // ── 2. Email approval requests ───────────────────────────────────────
        Schema::create('vapt_email_approvals', function (Blueprint $table) {
            $table->id();

            $table->foreignId('scan_id')
                ->constrained('vapt_scans')
                ->cascadeOnDelete();

            $table->foreignId('requested_by')           // user who clicked "Email Owner"
                ->constrained('users')
                ->cascadeOnDelete();

            $table->foreignId('reviewed_by')            // admin who approved/rejected
                ->nullable()
                ->constrained('users')
                ->nullOnDelete();

            // pending | approved | rejected
            $table->string('status')->default('pending');

            // Optional note from admin when rejecting
            $table->text('admin_note')->nullable();

            // When admin acted
            $table->timestamp('reviewed_at')->nullable();

            $table->timestamps();

            // A scan can only have one pending approval at a time
            $table->unique(['scan_id', 'status'], 'one_pending_per_scan');
        });
    }

    public function down(): void
    {
        Schema::table('vapt_scans', function (Blueprint $table) {
            $table->dropColumn(['owner_name', 'owner_email']);
        });
        Schema::dropIfExists('vapt_email_approvals');
    }
};