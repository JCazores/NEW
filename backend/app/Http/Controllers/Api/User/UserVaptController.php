<?php

namespace App\Http\Controllers\Api\User;

use App\Http\Controllers\Controller;
use App\Jobs\RunNetworkScan;
use App\Mail\VaptOwnerReportMail;
use App\Models\VaptEmailApproval;
use App\Models\VaptScan;
use App\Models\VaptVulnerability;
use Barryvdh\DomPDF\Facade\Pdf;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;

class UserVaptController extends Controller
{
    // ── Helpers ───────────────────────────────────────────────────────────────

    private function startScan(Request $request, string $type)
    {
        $request->validate([
            'target'      => 'required|string|max:255',
            'scan_type'   => 'required|in:quick,full,vuln',
            'owner_name'  => 'nullable|string|max:255',
            'owner_email' => 'nullable|email|max:255',
        ]);

        $scan = VaptScan::create([
            'user_id'     => Auth::id(),
            'type'        => $type,
            'target'      => $request->target,
            'scan_type'   => $request->scan_type,
            'owner_name'  => $request->owner_name,
            'owner_email' => $request->owner_email,
            'status'      => 'queued',
            'progress'    => 0,
            'phase'       => 'Queued',
        ]);

        RunNetworkScan::dispatch($scan);

        return response()->json(['message' => 'Scan queued.', 'data' => $scan], 201);
    }

    /**
     * ─────────────────────────────────────────────────────────────────────────
     * LIVE STATUS ENDPOINT  →  GET /user/vapt/{type}/scans/{id}/status
     *
     * Frontend polls this every 2–3 s while a scan is running.
     * Returns lightweight progress data — no vuln list until done.
     * Safe to call after a page reload; just re-pass the scan ID.
     * ─────────────────────────────────────────────────────────────────────────
     */
    private function getScanStatus(string $type, int $id)
    {
        $scan = VaptScan::where('user_id', Auth::id())
            ->where('type', $type)
            ->select([
                'id', 'target', 'scan_type', 'status',
                'phase', 'progress', 'phase_log', 'error_message',
                'created_at', 'updated_at',
            ])
            ->findOrFail($id);

        $payload = [
            'id'            => $scan->id,
            'target'        => $scan->target,
            'scan_type'     => $scan->scan_type,
            'status'        => $scan->status,
            'phase'         => $scan->phase,
            'progress'      => $scan->progress ?? 0,
            'phase_log'     => $scan->phase_log ?? [],
            'error_message' => $scan->error_message,
            'updated_at'    => $scan->updated_at?->toISOString(),
        ];

        if ($scan->status === 'done') {
            $payload['vulns'] = VaptVulnerability::where('scan_id', $scan->id)
                ->selectRaw("
                    SUM(severity = 'critical') as critical,
                    SUM(severity = 'high')     as high,
                    SUM(severity = 'medium')   as medium,
                    SUM(severity = 'low')      as low
                ")
                ->first()
                ->toArray();
        }

        return response()->json(['data' => $payload]);
    }

    private function userScans(string $type)
    {
        $scans = VaptScan::where('user_id', Auth::id())
            ->where('type', $type)
            ->withCount([
                'vulnerabilities as vuln_critical' => fn($q) => $q->where('severity', 'critical'),
                'vulnerabilities as vuln_high'     => fn($q) => $q->where('severity', 'high'),
                'vulnerabilities as vuln_medium'   => fn($q) => $q->where('severity', 'medium'),
                'vulnerabilities as vuln_low'      => fn($q) => $q->where('severity', 'low'),
            ])
            ->latest()
            ->get()
            ->map(fn($s) => [
                'id'            => $s->id,
                'target'        => $s->target,
                'scan_type'     => $s->scan_type,
                'status'        => $s->status,
                'phase'         => $s->phase,
                'progress'      => $s->progress ?? 0,
                'phase_log'     => $s->phase_log ?? [],
                'error_message' => $s->error_message,
                'date'          => $s->created_at->toDateString(),
                'created_at'    => $s->created_at->toISOString(),
                'vulns'         => $s->status === 'done' ? [
                    'critical' => $s->vuln_critical,
                    'high'     => $s->vuln_high,
                    'medium'   => $s->vuln_medium,
                    'low'      => $s->vuln_low,
                ] : null,
            ]);

        return response()->json(['data' => $scans]);
    }

    private function showScan(string $type, int $id)
    {
        $scan = VaptScan::with('vulnerabilities')
            ->where('user_id', Auth::id())
            ->where('type', $type)
            ->findOrFail($id);

        return response()->json(['data' => $scan]);
    }

    private function userVulnerabilities(string $type)
    {
        $vulns = VaptVulnerability::whereHas(
            'scan',
            fn($q) => $q->where('user_id', Auth::id())->where('type', $type)
        )
            ->latest()
            ->get()
            ->map(fn($v) => [
                'id'          => $v->id,
                'cve_id'      => $v->cve_id,
                'severity'    => $v->severity,
                'host'        => $v->host,
                'port'        => $v->port,
                'service'     => $v->service,
                'title'       => $v->title,
                'description' => $v->description,
                'cvss'        => $v->cvss,
                'status'      => $v->status,
                'scan_id'     => $v->scan_id,
            ]);

        return response()->json(['data' => $vulns]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // EXPORT — JSON (kept for backwards compatibility)
    // ─────────────────────────────────────────────────────────────────────────

    private function exportScan(string $type, int $id)
    {
        $scan = VaptScan::with('vulnerabilities')
            ->where('user_id', Auth::id())
            ->where('type', $type)
            ->where('status', 'done')
            ->findOrFail($id);

        return response()->json(['data' => $scan]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // EXPORT — PDF
    // Generates and streams a professional branded PDF report.
    // ─────────────────────────────────────────────────────────────────────────

    private function exportScanPdf(string $type, int $id)
    {
        $scan = VaptScan::with(['vulnerabilities', 'user'])
            ->where('user_id', Auth::id())
            ->where('type', $type)
            ->where('status', 'done')
            ->findOrFail($id);

        $vulns = $scan->vulnerabilities;

        $pdf = Pdf::loadView('pdf.vapt-report', compact('scan', 'vulns'))
            ->setPaper('a4', 'portrait')
            ->setOptions([
                'isHtml5ParserEnabled' => true,
                'isRemoteEnabled'      => false,
                'defaultFont'          => 'DejaVu Sans',
                'dpi'                  => 150,
            ]);

        $filename = 'VAPT-Report-'
            . str_replace(['/', '\\', ' ', '.'], '-', $scan->target)
            . '-' . $scan->created_at->format('Y-m-d')
            . '.pdf';

        return $pdf->download($filename);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // REQUEST EMAIL APPROVAL
    // Saves owner name + email AND submits approval request in one single call.
    // ─────────────────────────────────────────────────────────────────────────

    private function requestEmailApproval(Request $request, string $type, int $id)
    {
        $request->validate([
            'owner_name'  => 'nullable|string|max:255',
            'owner_email' => 'required|email|max:255',
        ]);

        $scan = VaptScan::where('user_id', Auth::id())
            ->where('type', $type)
            ->where('status', 'done')
            ->findOrFail($id);

        // Save owner info to the scan
        $scan->update([
            'owner_name'  => $request->owner_name,
            'owner_email' => $request->owner_email,
        ]);

        // Check if there's already a pending approval
        $existing = VaptEmailApproval::where('scan_id', $scan->id)
            ->where('status', 'pending')
            ->first();

        if ($existing) {
            // Update owner info on the scan (user may have corrected the email)
            return response()->json([
                'message' => 'Approval request already pending. Owner email updated to ' . $request->owner_email . '.',
            ]);
        }

        VaptEmailApproval::create([
            'scan_id'      => $scan->id,
            'requested_by' => Auth::id(),
            'status'       => 'pending',
        ]);

        return response()->json([
            'message' => 'Approval request submitted. An admin will review and send the report to ' . $request->owner_email . '.',
        ]);
    }

    // ── Mobile ────────────────────────────────────────────────────────────────

    public function mobileIndex()                    { return $this->userScans('mobile'); }
    public function mobileScan(Request $r)           { return $this->startScan($r, 'mobile'); }
    public function mobileScans()                    { return $this->userScans('mobile'); }
    public function mobileScanShow(int $s)           { return $this->showScan('mobile', $s); }
    public function mobileScanStatus(int $s)         { return $this->getScanStatus('mobile', $s); }
    public function mobileVulnerabilities()          { return $this->userVulnerabilities('mobile'); }

    // ── Web ───────────────────────────────────────────────────────────────────

    public function webIndex()                       { return $this->userScans('web'); }
    public function webScan(Request $r)              { return $this->startScan($r, 'web'); }
    public function webScans()                       { return $this->userScans('web'); }
    public function webScanShow(int $s)              { return $this->showScan('web', $s); }
    public function webScanStatus(int $s)            { return $this->getScanStatus('web', $s); }
    public function webVulnerabilities()             { return $this->userVulnerabilities('web'); }

    // ── Network ───────────────────────────────────────────────────────────────

    public function networkIndex()                   { return $this->userScans('network'); }
    public function networkScan(Request $r)          { return $this->startScan($r, 'network'); }
    public function networkScans()                   { return $this->userScans('network'); }
    public function networkScanShow(int $s)          { return $this->showScan('network', $s); }
    public function networkScanStatus(int $s)        { return $this->getScanStatus('network', $s); }
    public function networkVulnerabilities()         { return $this->userVulnerabilities('network'); }
    public function networkExport(int $s)                        { return $this->exportScan('network', $s); }
    public function networkExportPdf(int $s)                     { return $this->exportScanPdf('network', $s); }
    public function networkRequestEmailApproval(Request $r, int $s) { return $this->requestEmailApproval($r, 'network', $s); }
    public function networkApprovalStatus(int $id)
    {
        $scan     = VaptScan::where('user_id', Auth::id())->where('type','network')->findOrFail($id);
        $approval = VaptEmailApproval::where('scan_id', $scan->id)->latest()->first();
        return response()->json(['data' => $approval ? ['status'=>$approval->status,'admin_note'=>$approval->admin_note,'reviewed_at'=>$approval->reviewed_at?->toISOString()] : null]);
    }
}