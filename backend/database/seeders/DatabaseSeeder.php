<?php
namespace Database\Seeders;
use App\Models\User;
use Illuminate\Database\Seeder;
class DatabaseSeeder extends Seeder
{
    public function run(): void
    {
        User::firstOrCreate(
            ['email' => 'admin@gmail.com'],
            [
                'name' => 'admin',
                'password' => bcrypt('admin123'),
                'email_verified_at' => now(),
            ]
        );
    }
}
