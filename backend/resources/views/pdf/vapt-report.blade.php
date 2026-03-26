<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body {
    font-family: 'DejaVu Sans', Arial, sans-serif;
    font-size: 10px; color: #111; background: #fff;
    line-height: 1.4; padding: 18px 22px;
}
.top-bar { display:table; width:100%; border-bottom:2px solid #1a5276; padding-bottom:4px; margin-bottom:8px; }
.top-bar-left  { display:table-cell; vertical-align:bottom; }
.top-bar-right { display:table-cell; text-align:right; vertical-align:bottom; font-size:9px; color:#555; }
.report-title  { font-size:16px; font-weight:bold; color:#1a5276; }
.report-sub    { font-size:9px; color:#777; margin-top:1px; }

.meta-row  { display:table; width:100%; background:#f0f4f8; border:1px solid #c8d8e8; padding:5px 8px; margin-bottom:8px; }
.meta-cell { display:table-cell; width:25%; font-size:9px; }
.meta-label { color:#666; text-transform:uppercase; font-size:8px; letter-spacing:0.5px; }
.meta-value { font-weight:bold; color:#111; margin-top:1px; }

.totals-bar { display:table; width:100%; margin-bottom:8px; border-collapse:collapse; }
.totals-bar td { display:table-cell; width:25%; text-align:center; padding:4px 0; font-size:11px; font-weight:bold; border:1px solid #ccc; }
.t-critical { background:#fde8e8; color:#c00; }
.t-high     { background:#fdebd0; color:#b45309; }
.t-medium   { background:#fef9e7; color:#7d6608; }
.t-low      { background:#eaf5ea; color:#1e6b1e; }
.totals-num { font-size:18px; display:block; line-height:1.1; }
.totals-lbl { font-size:8px; font-weight:normal; display:block; text-transform:uppercase; letter-spacing:0.5px; }

.section-title { font-size:10px; font-weight:bold; color:#1a5276; background:#dce6f1; border-left:3px solid #1a5276; padding:3px 7px; margin:8px 0 4px; }

table.tbl { width:100%; border-collapse:collapse; font-size:9.5px; margin-bottom:6px; }
table.tbl th { background:#dce6f1; border:1px solid #9dc3e6; padding:3px 6px; font-weight:bold; text-align:left; }
table.tbl td { border:1px solid #ccc; padding:3px 6px; vertical-align:top; }
table.tbl tr:nth-child(even) td { background:#f7f7f7; }

.host-label { font-size:10px; font-weight:bold; color:#1a5276; font-family:monospace; margin:6px 0 2px; border-bottom:1px solid #aed6f1; padding-bottom:1px; }
.sc { color:#c00000; font-weight:bold; }
.sh { color:#b45309; font-weight:bold; }
.sm { color:#7d6608; font-weight:bold; }
.sl { color:#1e6b1e; font-weight:bold; }

.sol-box { background:#fffde7; border-left:2px solid #f0a500; padding:2px 5px; margin-top:3px; font-size:9px; color:#4a3800; }
.nvd-url { font-size:8.5px; color:#1a5276; word-break:break-all; margin-top:2px; }

.exec-box { border:1px solid #c8d8e8; background:#f8fbff; padding:7px 10px; margin-bottom:8px; }
.exec-title { font-size:10px; font-weight:bold; color:#1a5276; margin-bottom:4px; border-bottom:1px solid #dce6f1; padding-bottom:2px; }
.exec-body  { font-size:9.5px; color:#222; line-height:1.6; }

.footer { margin-top:10px; border-top:1px solid #ccc; padding-top:3px; font-size:8px; color:#aaa; text-align:center; }
</style>
</head>
<body>

@php
    $total  = $vulns->count();
    $open   = $vulns->where('status','open')->count();
    $resolved = $vulns->where('status','resolved')->count();
    $c = $vulns->where('severity','critical')->count();
    $h = $vulns->where('severity','high')->count();
    $m = $vulns->where('severity','medium')->count();
    $l = $vulns->where('severity','low')->count();
    $byHost = $vulns->groupBy('host');
    $score  = $c*4 + $h*3 + $m*2 + $l;
    $risk   = $score===0 ? 'Secure' : ($score<5 ? 'Low' : ($score<15 ? 'Moderate' : ($score<30 ? 'High' : 'Critical')));

    $sc = fn($s) => match($s) { 'critical'=>'sc','high'=>'sh','medium'=>'sm','low'=>'sl',default=>'' };

    $sol = fn($s, $cve) => match($s) {
        'critical' => 'Patch or isolate immediately. Do not expose to internet until resolved.' . ($cve ? " Patch advisory: nvd.nist.gov/vuln/detail/{$cve}" : ''),
        'high'     => 'Remediate within 7 days. Apply latest vendor patch or apply firewall compensating control.' . ($cve ? " Reference: nvd.nist.gov/vuln/detail/{$cve}" : ''),
        'medium'   => 'Remediate in next maintenance window. Review vendor advisory for patches.' . ($cve ? " Reference: nvd.nist.gov/vuln/detail/{$cve}" : ''),
        default    => 'Address during routine maintenance.' . ($cve ? " Reference: nvd.nist.gov/vuln/detail/{$cve}" : ''),
    };

    $order = ['critical'=>1,'high'=>2,'medium'=>3,'low'=>4];

    // Executive summary text
    if ($total === 0) {
        $execText = "A vulnerability assessment was conducted on {$scan->target} on {$scan->created_at->format('F j, Y')}. "
            . "The scan completed successfully and found no security vulnerabilities. "
            . "The target is considered secure at the time of this assessment. "
            . "It is recommended to run regular scans to maintain this security posture.";
    } else {
        $urgentPart = '';
        if ($c > 0) $urgentPart .= "{$c} Critical " . ($c===1?'issue requires':'issues require') . " immediate patching. ";
        if ($h > 0) $urgentPart .= "{$h} High " . ($h===1?'issue requires':'issues require') . " remediation within 7 days. ";
        $execText = "A vulnerability assessment was conducted on {$scan->target} on {$scan->created_at->format('F j, Y')}. "
            . "The scan identified {$total} " . ($total===1?'vulnerability':'vulnerabilities') . " across " . $byHost->count() . " " . ($byHost->count()===1?'host':'hosts') . ", "
            . "with an overall risk level of {$risk}. "
            . $urgentPart
            . "Currently {$open} " . ($open===1?'finding remains':'findings remain') . " open and {$resolved} " . ($resolved===1?'has been':'have been') . " resolved. "
            . "Immediate action is recommended for all Critical and High severity findings. "
            . "A prioritized remediation plan is provided in this report.";
    }
@endphp

{{-- HEADER --}}
<div class="top-bar">
    <div class="top-bar-left">
        <div class="report-title">Network Vulnerability Assessment Report</div>
        <div class="report-sub">ServerSentinel &middot; Sorted by host &middot; Confidential</div>
    </div>
    <div class="top-bar-right">
        {{ $scan->created_at->format('d M Y H:i') }}<br>
        Risk Level: <strong>{{ $risk }}</strong>
    </div>
</div>

{{-- META --}}
<div class="meta-row">
    <div class="meta-cell">
        <div class="meta-label">Target</div>
        <div class="meta-value" style="font-family:monospace;">{{ $scan->target }}</div>
    </div>
    <div class="meta-cell">
        <div class="meta-label">Scan Type</div>
        <div class="meta-value">{{ ucfirst($scan->scan_type) }}</div>
    </div>
    <div class="meta-cell">
        <div class="meta-label">Duration</div>
        <div class="meta-value">{{ $scan->created_at->diffForHumans($scan->updated_at, true) }}</div>
    </div>
    <div class="meta-cell">
        <div class="meta-label">Prepared For</div>
        <div class="meta-value">{{ $scan->user->name }}</div>
    </div>
</div>

{{-- TOTALS --}}
<table class="totals-bar">
    <tr>
        <td class="t-critical"><span class="totals-num">{{ $c }}</span><span class="totals-lbl">Critical &middot; 9.0–10.0</span></td>
        <td class="t-high">    <span class="totals-num">{{ $h }}</span><span class="totals-lbl">High &middot; 7.0–8.9</span></td>
        <td class="t-medium">  <span class="totals-num">{{ $m }}</span><span class="totals-lbl">Medium &middot; 4.0–6.9</span></td>
        <td class="t-low">     <span class="totals-num">{{ $l }}</span><span class="totals-lbl">Low &middot; 0.1–3.9</span></td>
    </tr>
</table>

{{-- VERDICT --}}
@if ($total === 0)
<div style="display:table;width:100%;background:#eafaf1;border:1.5px solid #27ae60;padding:7px 12px;margin-bottom:8px;">
    <div style="display:table-cell;vertical-align:middle;width:28px;font-size:18px;">&#x2705;</div>
    <div style="display:table-cell;vertical-align:middle;">
        <div style="font-size:11px;font-weight:bold;color:#1e6b1e;">PASSED &mdash; No Vulnerabilities Detected</div>
        <div style="font-size:9px;color:#2e7d32;margin-top:1px;">
            The target <strong style="font-family:monospace;">{{ $scan->target }}</strong> passed all vulnerability checks on {{ $scan->created_at->format('d M Y') }}. No security issues were identified at the time of this scan.
        </div>
    </div>
</div>
@else
<div style="display:table;width:100%;background:#fdf2f2;border:1.5px solid #c0392b;padding:7px 12px;margin-bottom:8px;">
    <div style="display:table-cell;vertical-align:middle;width:28px;font-size:18px;">&#x274C;</div>
    <div style="display:table-cell;vertical-align:middle;">
        <div style="font-size:11px;font-weight:bold;color:#c0392b;">NOT PASSED &mdash; {{ $total }} Vulnerabilit{{ $total!==1?'ies':'y' }} Detected &nbsp;&nbsp; <span style="font-weight:normal;font-size:9px;">Open: {{ $open }} &nbsp;&middot;&nbsp; Resolved: {{ $resolved }}</span></div>
        <div style="font-size:9px;color:#922b21;margin-top:1px;">
            The target <strong style="font-family:monospace;">{{ $scan->target }}</strong> did <strong>not pass</strong> the assessment on {{ $scan->created_at->format('d M Y') }}.
            @if ($c > 0) <strong>{{ $c }} Critical</strong> issue{{ $c!==1?'s':'' }} require immediate attention. @endif
            @if ($h > 0) <strong>{{ $h }} High</strong> issue{{ $h!==1?'s':'' }} must be remediated within 7 days. @endif
            Review the findings and remediation plan below.
        </div>
    </div>
</div>
@endif

{{-- #1 — EXECUTIVE SUMMARY --}}
<div class="section-title">Executive Summary</div>
<div class="exec-box">
    <div class="exec-body">{{ $execText }}</div>
</div>

{{-- SUMMARY TABLE --}}
<div class="section-title">Summary of Scanned Hosts</div>
<table class="tbl">
    <thead>
        <tr>
            <th style="width:30%">Host</th>
            <th style="width:11%;text-align:center;" class="sc">Critical</th>
            <th style="width:11%;text-align:center;" class="sh">High</th>
            <th style="width:11%;text-align:center;" class="sm">Medium</th>
            <th style="width:11%;text-align:center;" class="sl">Low</th>
            <th style="width:13%;text-align:center;">Open</th>  {{-- #2 open/resolved --}}
            <th style="width:13%;text-align:center;">Resolved</th>
        </tr>
    </thead>
    <tbody>
        @forelse ($byHost as $host => $hv)
        <tr>
            <td style="font-family:monospace;font-weight:bold;">{{ $host }}</td>
            <td style="text-align:center;" class="sc">{{ $hv->where('severity','critical')->count() ?: '&mdash;' }}</td>
            <td style="text-align:center;" class="sh">{{ $hv->where('severity','high')->count()     ?: '&mdash;' }}</td>
            <td style="text-align:center;" class="sm">{{ $hv->where('severity','medium')->count()   ?: '&mdash;' }}</td>
            <td style="text-align:center;" class="sl">{{ $hv->where('severity','low')->count()      ?: '&mdash;' }}</td>
            <td style="text-align:center;color:#c0392b;font-weight:bold;">{{ $hv->where('status','open')->count()     ?: '&mdash;' }}</td>
            <td style="text-align:center;color:#1e6b1e;font-weight:bold;">{{ $hv->where('status','resolved')->count() ?: '&mdash;' }}</td>
        </tr>
        @empty
        <tr><td colspan="7" style="text-align:center;color:#888;">No hosts scanned.</td></tr>
        @endforelse
    </tbody>
</table>

@if ($total > 0)

{{-- #4 — REMEDIATION PRIORITY TABLE --}}
<div class="section-title">Remediation Priority Plan</div>
<table class="tbl">
    <thead>
        <tr>
            <th style="width:5%;text-align:center;">#</th>
            <th style="width:13%;text-align:center;">Severity</th>
            <th style="width:9%;text-align:center;">CVSS</th>
            <th style="width:20%">Finding</th>
            <th style="width:15%">Host:Port</th>
            <th style="width:12%;text-align:center;">Status</th>
            <th>Action Required</th>
        </tr>
    </thead>
    <tbody>
        @php $priority = $vulns->sortBy(fn($v) => [$order[$v->severity]??5, -$v->cvss])->values(); @endphp
        @foreach ($priority as $i => $v)
        <tr>
            <td style="text-align:center;font-weight:bold;">{{ $i+1 }}</td>
            <td style="text-align:center;" class="{{ $sc($v->severity) }}">{{ ucfirst($v->severity) }}</td>
            <td style="text-align:center;font-weight:bold;" class="{{ $sc($v->severity) }}">{{ $v->cvss }}</td>
            <td>
                {{ $v->title }}
                @if ($v->cve_id)
                    <br><span style="font-size:8px;color:#1a5276;font-family:monospace;">{{ $v->cve_id }}</span>
                @endif
            </td>
            <td style="font-family:monospace;font-size:9px;">{{ $v->host }}:{{ $v->port }}</td>
            <td style="text-align:center;">
                @if ($v->status === 'open')
                    <span style="color:#c0392b;font-weight:bold;">Open</span>
                @else
                    <span style="color:#1e6b1e;font-weight:bold;">Resolved</span>
                @endif
            </td>
            <td style="font-size:9px;">
                @if ($v->severity === 'critical') Patch or isolate immediately.
                @elseif ($v->severity === 'high')  Remediate within 7 days.
                @elseif ($v->severity === 'medium') Next maintenance window.
                @else Routine maintenance.
                @endif
                @if ($v->cve_id)
                    <div class="nvd-url">nvd.nist.gov/vuln/detail/{{ $v->cve_id }}</div>
                @endif
            </td>
        </tr>
        @endforeach
    </tbody>
</table>

{{-- DETAILED FINDINGS --}}
<div class="section-title">Detailed Findings &mdash; {{ $total }} Total &nbsp; <span style="font-weight:normal;font-size:9px;">Open: {{ $open }} &middot; Resolved: {{ $resolved }}</span></div>

@foreach ($byHost as $host => $hv)
    <div class="host-label">
        {{ $host }}
        &nbsp;&nbsp;
        <span style="font-size:9px;font-weight:normal;color:#555;">
            {{ $hv->where('status','open')->count() }} open &middot; {{ $hv->where('status','resolved')->count() }} resolved
        </span>
    </div>
    <table class="tbl">
        <thead>
            <tr>
                <th style="width:15%">Service</th>
                <th style="width:10%;text-align:center;">Severity</th>
                <th style="width:8%;text-align:center;">CVSS</th>
                <th style="width:10%;text-align:center;">Status</th>  {{-- #2 --}}
                <th>Description &amp; Solution</th>
            </tr>
        </thead>
        <tbody>
            @foreach ($hv->sortBy(fn($v) => $order[$v->severity] ?? 5) as $v)
            <tr>
                <td style="font-family:monospace;white-space:nowrap;">
                    {{ $v->service }}<br>
                    <span style="color:#888;font-size:8.5px;">port {{ $v->port }}/tcp</span>
                </td>
                <td style="text-align:center;" class="{{ $sc($v->severity) }}">{{ ucfirst($v->severity) }}</td>
                <td style="text-align:center;font-weight:bold;" class="{{ $sc($v->severity) }}">{{ $v->cvss }}</td>
                <td style="text-align:center;">
                    @if ($v->status === 'open')
                        <span style="color:#c0392b;font-weight:bold;">Open</span>
                    @else
                        <span style="color:#1e6b1e;font-weight:bold;">Resolved</span>
                    @endif
                </td>
                <td>
                    <strong>{{ $v->title }}</strong>
                    @if ($v->cve_id)
                        <span style="font-size:8.5px;color:#1a5276;font-family:monospace;margin-left:4px;">[{{ $v->cve_id }}]</span>
                    @endif
                    <br>
                    <span style="color:#333;">{{ $v->description }}</span>
                    <div class="sol-box">
                        <strong>Solution:</strong> {{ $sol($v->severity, $v->cve_id) }}
                        @if ($v->cve_id) {{-- #6 full NVD URL --}}
                            <div class="nvd-url">&#x1F517; nvd.nist.gov/vuln/detail/{{ $v->cve_id }}</div>
                        @endif
                    </div>
                </td>
            </tr>
            @endforeach
        </tbody>
    </table>
@endforeach

@endif

{{-- FOOTER --}}
<div class="footer">
    ServerSentinel &middot; Network VAPT Report &middot; {{ $scan->target }} &middot; Generated {{ now()->format('d M Y H:i') }} &middot; CONFIDENTIAL
</div>

</body>
</html>