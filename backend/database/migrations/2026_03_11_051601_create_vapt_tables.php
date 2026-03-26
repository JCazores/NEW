<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('vapt_scans', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->enum('type', ['mobile', 'web', 'network']);
            $table->string('target');
            $table->string('scan_type')->default('quick'); // quick | full | vuln | stealth
            $table->enum('status', ['queued', 'running', 'done', 'failed'])->default('queued');
            $table->timestamps();
        });

        Schema::create('vapt_vulnerabilities', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_id')->constrained('vapt_scans')->cascadeOnDelete();
            $table->string('cve_id')->nullable();
            $table->enum('severity', ['critical', 'high', 'medium', 'low']);
            $table->string('host')->nullable();
            $table->unsignedInteger('port')->nullable();
            $table->string('service')->nullable();
            $table->string('title');
            $table->text('description')->nullable();
            $table->decimal('cvss', 3, 1)->nullable();
            $table->enum('status', ['open', 'resolved'])->default('open');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('vapt_vulnerabilities');
        Schema::dropIfExists('vapt_scans');
    }
};