<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('categories', function (Blueprint $table) {
            $table->id();
            $table->string('name')->unique();
            $table->string('color')->default('gray'); // red, blue, yellow, purple, gray, green, indigo, orange
            $table->timestamps();
        });

        // Seed the 5 default categories
        DB::table('categories')->insert([
            ['name' => 'Military',     'color' => 'red',    'created_at' => now(), 'updated_at' => now()],
            ['name' => 'Schools',      'color' => 'blue',   'created_at' => now(), 'updated_at' => now()],
            ['name' => 'Government',   'color' => 'yellow', 'created_at' => now(), 'updated_at' => now()],
            ['name' => 'Municipality', 'color' => 'purple', 'created_at' => now(), 'updated_at' => now()],
            ['name' => 'Others',       'color' => 'gray',   'created_at' => now(), 'updated_at' => now()],
        ]);
    }

    public function down(): void
    {
        Schema::dropIfExists('categories');
    }
};