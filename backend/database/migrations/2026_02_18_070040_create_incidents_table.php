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
    Schema::create('incidents', function (Blueprint $table) {
        $table->id();
        $table->foreignId('monitor_id')->constrained()->cascadeOnDelete();
        $table->timestamp('started_at');
        $table->timestamp('resolved_at')->nullable();
        $table->enum('status', ['open', 'resolved'])->default('open');
        $table->text('reason')->nullable();
        $table->integer('down_duration_seconds')->nullable();
        $table->timestamps();
    });
}

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('incidents');
    }
};
