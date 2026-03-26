<?php

namespace App\Http\Controllers\Api\Admin;

use App\Http\Controllers\Controller;
use App\Mail\VaptOwnerReportMail;
use App\Models\VaptEmailApproval;
use App\Models\VaptScan;
use App\Models\VaptVulnerability;
use Barryvdh\DomPDF\Facade\Pdf;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;

class AdminVaptController extends Controller
{
    // ── Helpers ───────────────────────────────────────────────────────────────

    private function scans(string $type)
    {
        return VaptScan::with('user')
            ->where('type', $type)
            ->latest()
            ->get()
            ->map(fn($s) => [
                'id'          => $s->id,
                'user'        => $s->user?->name,
                'email'       => $s->user?->email,
                'target'      => $s->target,
                'scan_type'   => $s->scan_type,
                'status'      => $s->status,
                'date'        => $s->created_at->toDateString(),
                'created_at'  => $s->created_at->toISOString(),
                'owner_name'  => $s->owner_name,
                'owner_email' => $s->owner_email,
                'vulns'       => $s->status === 'done' ? [
                    'critical' => $s->vulnerabilities()->where('severity', 'critical')->count(),
                    'high'     => $s->vulnerabilities()->where('severity', 'high')->count(),
                    'medium'   => $s->vulnerabilities()->where('severity', 'medium')->count(),
                    'low'      => $s->vulnerabilities()->where('severity', 'low')->count(),
                ] : null,
            ]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // EMAIL APPROVAL — List pending approvals
    // ─────────────────────────────────────────────────────────────────────────

    public function pendingApprovals()
    {
        $approvals = VaptEmailApproval::with(['scan.user', 'scan.vulnerabilities', 'requester'])
            ->where('status', 'pending')
            ->latest()
            ->get()
            ->map(fn($a) => [
                'id'           => $a->id,
                'scan_id'      => $a->scan_id,
                'target'       => $a->scan?->target,
                'owner_name'   => $a->scan?->owner_name,
                'owner_email'  => $a->scan?->owner_email,
                'requested_by' => $a->requester?->name,
                'user_email'   => $a->requester?->email,
                'status'       => $a->status,
                'created_at'   => $a->created_at->toISOString(),
                'vuln_count'   => $a->scan?->vulnerabilities()->count() ?? 0,
                'critical'     => $a->scan?->vulnerabilities()->where('severity','critical')->count() ?? 0,
                'high'         => $a->scan?->vulnerabilities()->where('severity','high')->count() ?? 0,
            ]);

        return response()->json(['data' => $approvals]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // EMAIL APPROVAL — Approve and send PDF to owner
    // ─────────────────────────────────────────────────────────────────────────

    public function approveEmail(int $id)
    {
        try {
            $approval = VaptEmailApproval::with(['scan.user', 'scan.vulnerabilities'])
                ->where('status', 'pending')
                ->findOrFail($id);

            $scan  = $approval->scan;
            $vulns = $scan->vulnerabilities;

            if (empty($scan->owner_email)) {
                return response()->json([
                    'message' => 'No owner email set on this scan. Ask the user to re-submit the email request with an owner email.',
                ], 422);
            }

            // Generate PDF
            $pdf = Pdf::loadView('pdf.vapt-report', compact('scan', 'vulns'))
                ->setPaper('a4', 'portrait')
                ->setOptions([
                    'isHtml5ParserEnabled' => true,
                    'isRemoteEnabled'      => false,
                    'defaultFont'          => 'DejaVu Sans',
                    'dpi'                  => 150,
                ]);

            $tmpDir  = storage_path('app/temp');
            $tmpPath = $tmpDir . DIRECTORY_SEPARATOR . 'vapt-owner-' . $scan->id . '-' . time() . '.pdf';
            if (!is_dir($tmpDir)) mkdir($tmpDir, 0755, true);
            file_put_contents($tmpPath, $pdf->output());

            try {
                Mail::to($scan->owner_email, $scan->owner_name ?? 'Network Owner')
                    ->send(new VaptOwnerReportMail($scan, $vulns, $tmpPath));
            } finally {
                if (file_exists($tmpPath)) unlink($tmpPath);
            }

            $approval->update([
                'status'      => 'approved',
                'reviewed_by' => Auth::id(),
                'reviewed_at' => now(),
            ]);

            return response()->json([
                'message' => 'Report approved and sent to ' . $scan->owner_email,
            ]);

        } catch (\Throwable $e) {
            \Illuminate\Support\Facades\Log::error('[VAPT Approve] ' . $e->getMessage(), ['trace' => $e->getTraceAsString()]);
            return response()->json([
                'message' => 'Failed to approve: ' . $e->getMessage(),
            ], 500);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // EMAIL APPROVAL — Reject
    // ─────────────────────────────────────────────────────────────────────────

    public function rejectEmail(Request $request, int $id)
    {
        $request->validate(['note' => 'nullable|string|max:500']);

        $approval = VaptEmailApproval::where('status', 'pending')->findOrFail($id);

        $approval->update([
            'status'      => 'rejected',
            'reviewed_by' => Auth::id(),
            'reviewed_at' => now(),
            'admin_note'  => $request->note,
        ]);

        return response()->json(['message' => 'Email request rejected.']);
    }

    private function vulnerabilities(string $type)
    {
        return VaptVulnerability::with('scan.user')
            ->whereHas('scan', fn($q) => $q->where('type', $type))
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
                'user'        => $v->scan?->user?->name,
            ]);
    }

    private function resolve(string $type, int $id)
    {
        $vuln = VaptVulnerability::whereHas('scan', fn($q) => $q->where('type', $type))
            ->findOrFail($id);

        $vuln->update(['status' => 'resolved']);

        return response()->json(['message' => 'Vulnerability marked as resolved.']);
    }

    private function deleteVuln(string $type, int $id)
    {
        $vuln = VaptVulnerability::whereHas('scan', fn($q) => $q->where('type', $type))
            ->findOrFail($id);

        $vuln->delete();

        return response()->json(['message' => 'Vulnerability deleted.']);
    }

    private function deleteScan(string $type, int $id)
    {
        $scan = VaptScan::where('type', $type)->findOrFail($id);
        $scan->vulnerabilities()->delete();
        $scan->delete();

        return response()->json(['message' => 'Scan deleted.']);
    }

    private function export(string $type)
    {
        $scans = VaptScan::with(['user', 'vulnerabilities'])
            ->where('type', $type)
            ->where('status', 'done')
            ->latest()
            ->get();

        return response()->json(['data' => $scans]);
    }

    // ── Mobile ────────────────────────────────────────────────────────────────

    public function mobileScans()
    {
        return response()->json(['data' => $this->scans('mobile')]);
    }

    public function mobileScanShow(int $scan)
    {
        $s = VaptScan::with(['user', 'vulnerabilities'])
            ->where('type', 'mobile')
            ->findOrFail($scan);

        return response()->json(['data' => $s]);
    }

    public function mobileVulnerabilities()
    {
        return response()->json(['data' => $this->vulnerabilities('mobile')]);
    }

    public function mobileResolve(int $vuln)
    {
        return $this->resolve('mobile', $vuln);
    }

    public function mobileDeleteVuln(int $vuln)
    {
        return $this->deleteVuln('mobile', $vuln);
    }

    public function mobileDeleteScan(int $scan)
    {
        return $this->deleteScan('mobile', $scan);
    }

    public function mobileExport()
    {
        return $this->export('mobile');
    }

    // ── Web ───────────────────────────────────────────────────────────────────

    public function webScans()
    {
        return response()->json(['data' => $this->scans('web')]);
    }

    public function webScanShow(int $scan)
    {
        $s = VaptScan::with(['user', 'vulnerabilities'])
            ->where('type', 'web')
            ->findOrFail($scan);

        return response()->json(['data' => $s]);
    }

    public function webVulnerabilities()
    {
        return response()->json(['data' => $this->vulnerabilities('web')]);
    }

    public function webResolve(int $vuln)
    {
        return $this->resolve('web', $vuln);
    }

    public function webDeleteVuln(int $vuln)
    {
        return $this->deleteVuln('web', $vuln);
    }

    public function webDeleteScan(int $scan)
    {
        return $this->deleteScan('web', $scan);
    }

    public function webExport()
    {
        return $this->export('web');
    }

    // ── Network ───────────────────────────────────────────────────────────────

    public function networkScans()
    {
        return response()->json(['data' => $this->scans('network')]);
    }

    public function networkScanShow(int $scan)
    {
        $s = VaptScan::with(['user', 'vulnerabilities'])
            ->where('type', 'network')
            ->findOrFail($scan);

        return response()->json(['data' => $s]);
    }

    public function networkVulnerabilities()
    {
        return response()->json(['data' => $this->vulnerabilities('network')]);
    }

    public function networkResolve(int $vuln)
    {
        return $this->resolve('network', $vuln);
    }

    public function networkDeleteVuln(int $vuln)
    {
        return $this->deleteVuln('network', $vuln);
    }

    public function networkDeleteScan(int $scan)
    {
        return $this->deleteScan('network', $scan);
    }

    public function networkExport()
    {
        return $this->export('network');
    }

    // Admin PDF export for a specific scan (used in approval preview)
    public function networkExportScanPdf(int $scan)
    {
        $s     = VaptScan::with(['vulnerabilities', 'user'])->where('type','network')->findOrFail($scan);
        $vulns = $s->vulnerabilities;

        $pdf = Pdf::loadView('pdf.vapt-report', ['scan' => $s, 'vulns' => $vulns])
            ->setPaper('a4', 'portrait')
            ->setOptions(['isHtml5ParserEnabled'=>true,'isRemoteEnabled'=>false,'defaultFont'=>'DejaVu Sans','dpi'=>150]);

        $filename = 'VAPT-Report-' . str_replace(['/',' ','.'], '-', $s->target) . '-' . $s->created_at->format('Y-m-d') . '.pdf';
        return $pdf->download($filename);
    }
}