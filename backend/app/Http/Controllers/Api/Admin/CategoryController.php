<?php

namespace App\Http\Controllers\Api\Admin;

use App\Http\Controllers\Controller;
use App\Models\Category;
use App\Models\Monitor;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;

class CategoryController extends Controller
{
    /**
     * Ensure "Others" always exists.
     */
    private function ensureOthers(): void
    {
        Category::firstOrCreate(
            ['name' => 'Others'],
            ['color' => 'gray']
        );
    }

    public function index()
    {
        $this->ensureOthers();

        return response()->json([
            'data' => Category::orderBy('name')->get(),
        ]);
    }

    public function store(Request $request)
    {
        $this->ensureOthers();

        $data = $request->validate([
            'name'  => ['required', 'string', 'max:50', Rule::unique('categories', 'name')],
            'color' => ['required', 'string', 'max:30'],
        ]);

        $name = ucfirst(trim($data['name']));

        // Prevent using reserved name "Others"
        if (strtolower($name) === 'others') {
            return response()->json([
                'message' => '"Others" is a system category and already exists.'
            ], 422);
        }

        // extra safety: prevent duplicates by case-insensitive name
        $exists = Category::whereRaw('LOWER(name) = ?', [strtolower($name)])->exists();
        if ($exists) {
            return response()->json(['message' => 'Category already exists.'], 422);
        }

        $category = Category::create([
            'name'  => $name,
            'color' => $data['color'],
        ]);

        return response()->json([
            'message' => 'Category created successfully.',
            'data'    => $category,
        ], 201);
    }

    public function destroy(Category $category)
    {
        // Do NOT allow deleting Others
        if (strtolower($category->name) === 'others') {
            return response()->json([
                'message' => '"Others" is a system category and cannot be deleted.'
            ], 422);
        }

        try {
            DB::transaction(function () use ($category) {
                // Always ensure Others exists before moving monitors
                $this->ensureOthers();

                // Move monitors using this category to "Others"
                Monitor::where('category', $category->name)
                    ->update(['category' => 'Others']);

                $category->delete();
            });

            return response()->json([
                'message' => 'Category deleted successfully.',
            ]);
        } catch (\Throwable $e) {
            return response()->json([
                'message' => 'Failed to delete category.',
                'error'   => $e->getMessage(),
            ], 500);
        }
    }
}