<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
{
    Schema::create('monitors', function (Blueprint $table) {
        $table->id();
        $table->foreignId('user_id')->constrained()->cascadeOnDelete();
        $table->string('name');
        $table->string('url');
        $table->integer('check_interval_seconds')->default(2);
        $table->boolean('is_active')->default(true);
        $table->enum('last_status', ['up', 'down', 'unknown'])->default('unknown');
        $table->timestamp('last_checked_at')->nullable();
        $table->integer('last_response_time_ms')->nullable();
        $table->integer('last_http_code')->nullable();
        $table->decimal('uptime_percentage', 5, 2)->default(100.00);
        $table->timestamps();
    });
}

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('monitors');
    }
};
