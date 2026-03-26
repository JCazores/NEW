<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::table('incidents', function (Blueprint $table) {
            $table->string('error_type')->nullable()->after('status'); // timeout, dns, ssl, http_error, connection
            $table->integer('http_status_code')->nullable()->after('error_type');
            $table->text('error_message')->nullable()->after('http_status_code');
        });
    }

    public function down()
    {
        Schema::table('incidents', function (Blueprint $table) {
            $table->dropColumn(['error_type', 'http_status_code', 'error_message']);
        });
    }
};