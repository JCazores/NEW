<?php

use Illuminate\Support\Facades\Route;

// Auth
use App\Http\Controllers\AuthController;

// Admin controllers
use App\Http\Controllers\Api\Admin\UserController as AdminUserController;
use App\Http\Controllers\Api\Admin\MonitorController as AdminMonitorController;
use App\Http\Controllers\Api\Admin\IncidentController as AdminIncidentController;
use App\Http\Controllers\Api\Admin\CategoryController as AdminCategoryController;

// User controllers
use App\Http\Controllers\Api\User\MonitorController as UserMonitorController;
use App\Http\Controllers\Api\User\IncidentController as UserIncidentController;

// Dashboard & Stats controllers
use App\Http\Controllers\AdminController;
use App\Http\Controllers\UserController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
*/

// Public routes
Route::post('/login', [AuthController::class, 'login']);
Route::post('/verify-otp', [AuthController::class, 'verifyOtp']);
Route::post('/resend-otp', [AuthController::class, 'resendOtp']);

// Protected routes
Route::middleware('auth:sanctum')->group(function () {
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::get('/user', [AuthController::class, 'me']);

    // Shared: categories
    Route::get('/categories', [AdminCategoryController::class, 'index']);

    // User routes
    Route::prefix('user')->group(function () {
        Route::get('/monitors', [UserMonitorController::class, 'index']);
        Route::post('/monitors', [UserMonitorController::class, 'store']);
        Route::delete('/monitors/{monitor}', [UserMonitorController::class, 'destroy']);

        Route::get('/incidents', [UserIncidentController::class, 'index']);

        Route::get('/dashboard', [UserController::class, 'dashboard']);
        Route::get('/monitor-stats', [UserController::class, 'getMonitorStats']);
        Route::get('/incident-stats', [UserController::class, 'getIncidentStats']);
        Route::get('/incidents-by-cause', [UserController::class, 'getIncidentsByCause']);
        Route::get('/export-incidents-pdf', [UserController::class, 'exportIncidentsPdf']);
    });
});

// Admin routes
Route::middleware(['auth:sanctum', 'admin'])->prefix('admin')->group(function () {

    // Dashboard & Charts
    Route::get('/dashboard', [AdminController::class, 'dashboard']);
    Route::get('/monitor-stats', [AdminController::class, 'getMonitorStats']);
    Route::get('/incident-stats', [AdminController::class, 'getIncidentStats']);

    // Users management
    Route::get('/users', [AdminUserController::class, 'index']);
    Route::post('/users', [AdminUserController::class, 'store']);
    Route::delete('/users/{user}', [AdminUserController::class, 'destroy']);
    Route::patch('/users/{user}/status', [AdminUserController::class, 'updateStatus']);
    Route::post('/users/resend-otp', [AdminUserController::class, 'resendOtp']);
    Route::patch('/users/{user}/permissions', [AdminController::class, 'updatePermissions']);

    // Monitors management
    Route::get('/monitors', [AdminMonitorController::class, 'index']);
    Route::post('/monitors', [AdminMonitorController::class, 'store']);
    Route::put('/monitors/{monitor}', [AdminMonitorController::class, 'update']);
    Route::delete('/monitors/{monitor}', [AdminMonitorController::class, 'destroy']);
    Route::post('/monitors/{monitor}/toggle', [AdminMonitorController::class, 'toggle']);
    Route::get('/monitors/users', [AdminMonitorController::class, 'getUsers']);

    // Categories management
    Route::get('/categories', [AdminCategoryController::class, 'index']);
    Route::post('/categories', [AdminCategoryController::class, 'store']);
    Route::delete('/categories/{category}', [AdminCategoryController::class, 'destroy']);

    // Incidents
    Route::get('/incidents', [AdminIncidentController::class, 'index']);
    Route::get('/incidents/stats', [AdminIncidentController::class, 'stats']);
    Route::patch('/incidents/{incident}/root-cause', [AdminIncidentController::class, 'updateRootCause']);

    // Dashboard Charts & Export
    Route::get('/incidents-by-cause', [AdminController::class, 'getIncidentsByCause']);
    Route::get('/incidents-by-user', [AdminController::class, 'getIncidentsByUser']);
    Route::get('/export-incidents-pdf', [AdminController::class, 'exportIncidentsPdf']);
});

// System Health Routes
Route::middleware('auth:sanctum')->get('/user/system-health', [\App\Http\Controllers\SystemHealthController::class, 'userHealth']);
Route::middleware(['auth:sanctum', 'admin'])->get('/admin/system-health', [\App\Http\Controllers\SystemHealthController::class, 'adminHealth']);

// ─── VAPT Routes ─────────────────────────────────────────────────────────────
use App\Http\Controllers\Api\User\UserVaptController;
use App\Http\Controllers\Api\Admin\AdminVaptController;

Route::middleware('auth:sanctum')->prefix('user/vapt')->group(function () {

    // Network
    Route::get   ('network/scans',                          [UserVaptController::class, 'networkScans']);
    Route::post  ('network/scan',                           [UserVaptController::class, 'networkScan']);
    Route::get   ('network/scans/{id}/status',              [UserVaptController::class, 'networkScanStatus']);
    Route::get   ('network/scans/{id}',                     [UserVaptController::class, 'networkScanShow']);
    Route::get   ('network/vulnerabilities',                [UserVaptController::class, 'networkVulnerabilities']);
    Route::get   ('network/export/{id}/pdf',                [UserVaptController::class, 'networkExportPdf']);
    Route::post  ('network/export/{id}/request-email',      [UserVaptController::class, 'networkRequestEmailApproval']);
    Route::get   ('network/export/{id}/approval-status',    [UserVaptController::class, 'networkApprovalStatus']);

    // Web
    Route::get   ('web/scans',                              [UserVaptController::class, 'webScans']);
    Route::post  ('web/scan',                               [UserVaptController::class, 'webScan']);
    Route::get   ('web/scans/{id}/status',                  [UserVaptController::class, 'webScanStatus']);
    Route::get   ('web/scans/{id}',                         [UserVaptController::class, 'webScanShow']);
    Route::get   ('web/vulnerabilities',                    [UserVaptController::class, 'webVulnerabilities']);

    // Mobile
    Route::get   ('mobile/scans',                           [UserVaptController::class, 'mobileScans']);
    Route::post  ('mobile/scan',                            [UserVaptController::class, 'mobileScan']);
    Route::get   ('mobile/scans/{id}/status',               [UserVaptController::class, 'mobileScanStatus']);
    Route::get   ('mobile/scans/{id}',                      [UserVaptController::class, 'mobileScanShow']);
    Route::get   ('mobile/vulnerabilities',                 [UserVaptController::class, 'mobileVulnerabilities']);
});

Route::middleware(['auth:sanctum', 'admin'])->prefix('admin/vapt')->group(function () {
    Route::get   ('network/scans',                          [AdminVaptController::class, 'networkScans']);
    Route::get   ('network/scans/{id}',                     [AdminVaptController::class, 'networkScanShow']);
    Route::get   ('network/vulnerabilities',                [AdminVaptController::class, 'networkVulnerabilities']);
    Route::get   ('network/export/{id}/pdf',                [AdminVaptController::class, 'networkExportScanPdf']);
    Route::get   ('network/approvals',                      [AdminVaptController::class, 'pendingApprovals']);
    Route::post  ('network/approvals/{id}/approve',         [AdminVaptController::class, 'approveEmail']);
    Route::post  ('network/approvals/{id}/reject',          [AdminVaptController::class, 'rejectEmail']);
});

// ─── Admin VAPT extra routes (matching frontend URLs) ─────────────────────────
Route::middleware(['auth:sanctum', 'admin'])->prefix('admin/vapt')->group(function () {
    Route::get ('email-approvals',              [\App\Http\Controllers\Api\Admin\AdminVaptController::class, 'pendingApprovals']);
    Route::post('email-approvals/{id}/approve', [\App\Http\Controllers\Api\Admin\AdminVaptController::class, 'approveEmail']);
    Route::post('email-approvals/{id}/reject',  [\App\Http\Controllers\Api\Admin\AdminVaptController::class, 'rejectEmail']);
    Route::get ('network/export',               [\App\Http\Controllers\Api\Admin\AdminVaptController::class, 'networkExport']);
    Route::get ('network/export/scan/{id}/pdf', [\App\Http\Controllers\Api\Admin\AdminVaptController::class, 'networkExportScanPdf']);
    Route::delete('network/vulnerabilities/{id}', [\App\Http\Controllers\Api\Admin\AdminVaptController::class, 'networkDeleteVuln']);
    Route::delete('network/scans/{id}',           [\App\Http\Controllers\Api\Admin\AdminVaptController::class, 'networkDeleteScan']);
});
