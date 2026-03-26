<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('vapt_scans', function (Blueprint $table) {
            if (!Schema::hasColumn('vapt_scans', 'phase')) {
                $table->string('phase')->nullable()->after('status');
            }
            if (!Schema::hasColumn('vapt_scans', 'progress')) {
                $table->unsignedTinyInteger('progress')->default(0)->after('phase');
            }
            if (!Schema::hasColumn('vapt_scans', 'phase_log')) {
                $table->json('phase_log')->nullable()->after('progress');
            }
            if (!Schema::hasColumn('vapt_scans', 'error_message')) {
                $table->text('error_message')->nullable()->after('phase_log');
            }
        });
    }

    public function down(): void
    {
        Schema::table('vapt_scans', function (Blueprint $table) {
            $table->dropColumn(['phase', 'progress', 'phase_log', 'error_message']);
        });
    }
};