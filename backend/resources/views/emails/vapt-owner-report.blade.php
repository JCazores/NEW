<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network Vulnerability Report — {{ $scan->target }}</title>
</head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:40px 20px;">
<tr><td align="center">
<table width="620" cellpadding="0" cellspacing="0" style="max-width:620px;width:100%;">

  <!-- Header -->
  <tr>
    <td style="background:linear-gradient(135deg,#0f172a,#1e293b);border-radius:16px 16px 0 0;padding:36px 40px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td>
            <table cellpadding="0" cellspacing="0">
              <tr>
                <td style="background:rgba(6,182,212,0.15);border:1.5px solid rgba(6,182,212,0.35);border-radius:10px;width:44px;height:44px;text-align:center;vertical-align:middle;font-size:20px;">🛡</td>
                <td style="padding-left:12px;">
                  <div style="color:#e2e8f0;font-size:16px;font-weight:700;">ServerSentinel</div>
                  <div style="color:#475569;font-size:11px;margin-top:1px;">Security Platform</div>
                </td>
              </tr>
            </table>
          </td>
          <td align="right">
            <span style="background:rgba(6,182,212,0.12);border:1px solid rgba(6,182,212,0.3);color:#22d3ee;font-size:10px;letter-spacing:1.5px;text-transform:uppercase;padding:5px 12px;border-radius:20px;">
              Owner Report
            </span>
          </td>
        </tr>
      </table>
      <div style="margin-top:28px;">
        <div style="color:#94a3b8;font-size:11px;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:8px;">Network Vulnerability Assessment</div>
        <div style="color:#f1f5f9;font-size:26px;font-weight:800;line-height:1.2;letter-spacing:-0.3px;">
          Security Report for<br>
          <span style="color:#22d3ee;font-family:monospace;font-size:22px;">{{ $scan->target }}</span>
        </div>
      </div>
    </td>
  </tr>

  @php
    $total = $vulns->count();
    $c = $vulns->where('severity','critical')->count();
    $h = $vulns->where('severity','high')->count();
    $m = $vulns->where('severity','medium')->count();
    $l = $vulns->where('severity','low')->count();
    $score = $c*4 + $h*3 + $m*2 + $l;
    if ($score===0)     { $risk='Secure';    $riskBg='#f0fdf4'; $riskBorder='#bbf7d0'; $riskColor='#16a34a'; }
    elseif($score<5)    { $risk='Low Risk';  $riskBg='#f0f9ff'; $riskBorder='#bae6fd'; $riskColor='#0284c7'; }
    elseif($score<15)   { $risk='Moderate';  $riskBg='#fffbeb'; $riskBorder='#fde68a'; $riskColor='#d97706'; }
    elseif($score<30)   { $risk='High Risk'; $riskBg='#fff7ed'; $riskBorder='#fed7aa'; $riskColor='#ea580c'; }
    else                { $risk='Critical';  $riskBg='#fef2f2'; $riskBorder='#fecaca'; $riskColor='#dc2626'; }
  @endphp

  <!-- Risk banner -->
  <tr>
    <td style="background:{{ $riskBg }};border-left:4px solid {{ $riskColor }};border-right:1px solid {{ $riskBorder }};border-bottom:1px solid {{ $riskBorder }};padding:16px 24px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td>
            <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#64748b;margin-bottom:2px;">Overall Risk Level</div>
            <div style="font-size:20px;font-weight:800;color:{{ $riskColor }};">{{ $risk }}</div>
          </td>
          <td align="right" style="color:#64748b;font-size:13px;">
            {{ $total }} finding{{ $total!==1?'s':'' }} detected
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- Body -->
  <tr>
    <td style="background:#ffffff;padding:32px 40px;border:1px solid #e2e8f0;border-top:none;">

      <p style="color:#1e293b;font-size:15px;margin:0 0 8px;">
        Dear <strong>{{ $scan->owner_name ?? 'Network Owner' }}</strong>,
      </p>
      <p style="color:#475569;font-size:13px;line-height:1.7;margin:0 0 20px;">
        A vulnerability assessment has been conducted on your network
        <strong style="font-family:monospace;color:#0f172a;">{{ $scan->target }}</strong>
        on <strong>{{ $scan->updated_at->format('F j, Y') }}</strong> by
        <strong>{{ $scan->user->name }}</strong> ({{ $scan->user->email }})
        using the ServerSentinel security platform.
        The full report is attached as a PDF. A summary is provided below.
      </p>

      @if ($total === 0)
        <table width="100%" cellpadding="0" cellspacing="0" style="background:#f0fdf4;border:1.5px solid #bbf7d0;border-radius:12px;margin-bottom:24px;">
          <tr><td style="text-align:center;padding:24px;">
            <div style="font-size:32px;margin-bottom:8px;">✅</div>
            <div style="font-size:16px;font-weight:700;color:#16a34a;">No Vulnerabilities Detected</div>
            <div style="font-size:12px;color:#4ade80;margin-top:4px;">Your network passed all vulnerability checks.</div>
          </td></tr>
        </table>
      @else
        <!-- Summary grid -->
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#94a3b8;margin-bottom:12px;font-weight:600;">Findings Summary</div>
        <table width="100%" cellpadding="6" cellspacing="6" style="margin-bottom:20px;">
          <tr>
            <td width="25%" style="background:#fff5f5;border:1.5px solid #fecaca;border-radius:10px;text-align:center;padding:16px 8px;">
              <div style="font-size:28px;font-weight:800;color:#dc2626;line-height:1;">{{ $c }}</div>
              <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#94a3b8;margin-top:4px;">Critical</div>
            </td>
            <td width="25%" style="background:#fff7ed;border:1.5px solid #fed7aa;border-radius:10px;text-align:center;padding:16px 8px;">
              <div style="font-size:28px;font-weight:800;color:#ea580c;line-height:1;">{{ $h }}</div>
              <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#94a3b8;margin-top:4px;">High</div>
            </td>
            <td width="25%" style="background:#fffbeb;border:1.5px solid #fde68a;border-radius:10px;text-align:center;padding:16px 8px;">
              <div style="font-size:28px;font-weight:800;color:#d97706;line-height:1;">{{ $m }}</div>
              <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#94a3b8;margin-top:4px;">Medium</div>
            </td>
            <td width="25%" style="background:#f0f9ff;border:1.5px solid #bae6fd;border-radius:10px;text-align:center;padding:16px 8px;">
              <div style="font-size:28px;font-weight:800;color:#0284c7;line-height:1;">{{ $l }}</div>
              <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#94a3b8;margin-top:4px;">Low</div>
            </td>
          </tr>
        </table>

        @if ($c > 0)
        <div style="background:#fef2f2;border:1.5px solid #fecaca;border-radius:10px;padding:14px 16px;margin-bottom:16px;">
          <div style="font-size:12px;font-weight:700;color:#dc2626;margin-bottom:4px;">⚠️ Immediate Action Required</div>
          <div style="font-size:12px;color:#7f1d1d;line-height:1.6;">
            {{ $c }} critical vulnerabilit{{ $c===1?'y was':'ies were' }} found on your network.
            Critical vulnerabilities can be exploited remotely and may result in full system compromise.
            Please contact your security team immediately.
          </div>
        </div>
        @endif

        <!-- Top findings -->
        @php $top = $vulns->sortByDesc('cvss')->take(5); @endphp
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#94a3b8;margin-bottom:10px;font-weight:600;">
          Top Findings{{ $vulns->count()>5?' (Top 5)':'' }}
        </div>
        @foreach ($top as $v)
          @php $cols=['critical'=>['bg'=>'#fee2e2','color'=>'#dc2626'],'high'=>['bg'=>'#ffedd5','color'=>'#ea580c'],'medium'=>['bg'=>'#fef3c7','color'=>'#d97706'],'low'=>['bg'=>'#e0f2fe','color'=>'#0284c7']]; $col=$cols[$v->severity]??$cols['low']; @endphp
          <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e2e8f0;border-radius:8px;margin-bottom:8px;">
            <tr>
              <td width="50" style="background:{{ $col['bg'] }};text-align:center;padding:12px;vertical-align:middle;">
                <div style="font-size:14px;font-weight:800;color:{{ $col['color'] }};">{{ $v->cvss }}</div>
              </td>
              <td style="padding:10px 14px;">
                <div style="font-size:13px;font-weight:700;color:#0f172a;">{{ $v->title }}</div>
                <div style="font-size:11px;color:#94a3b8;margin-top:2px;font-family:monospace;">
                  {{ $v->host }}:{{ $v->port }} · {{ $v->service }}
                  @if($v->cve_id) · <span style="color:#4338ca;">{{ $v->cve_id }}</span>@endif
                </div>
              </td>
              <td width="80" align="right" style="padding:10px 14px;">
                @if($v->status==='open')
                  <span style="background:#fef2f2;border:1px solid #fecaca;color:#dc2626;font-size:10px;padding:2px 8px;border-radius:4px;font-weight:600;">Open</span>
                @else
                  <span style="background:#f0fdf4;border:1px solid #bbf7d0;color:#16a34a;font-size:10px;padding:2px 8px;border-radius:4px;font-weight:600;">Resolved</span>
                @endif
              </td>
            </tr>
          </table>
        @endforeach
        @if ($vulns->count()>5)
          <p style="font-size:12px;color:#64748b;text-align:center;margin-top:8px;">+ {{ $vulns->count()-5 }} more findings in the attached PDF.</p>
        @endif
      @endif

      <hr style="border:none;border-top:1px solid #f1f5f9;margin:24px 0;">

      <!-- PDF note -->
      <table width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:16px;">
        <tr>
          <td width="40" style="vertical-align:middle;font-size:24px;padding-right:12px;">📄</td>
          <td>
            <div style="font-size:13px;font-weight:700;color:#1e293b;">Full Report Attached</div>
            <div style="font-size:12px;color:#64748b;margin-top:2px;">
              The attached PDF contains the complete findings, CVE references, and remediation steps.
            </div>
          </td>
        </tr>
      </table>

      <p style="font-size:12px;color:#94a3b8;margin-top:20px;line-height:1.6;">
        This report was authorized by your security team and generated by ServerSentinel.
        If you have questions about these findings, please contact
        <strong>{{ $scan->user->name }}</strong> at <strong>{{ $scan->user->email }}</strong>.
      </p>
    </td>
  </tr>

  <!-- Footer -->
  <tr>
    <td style="background:#f8fafc;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 16px 16px;padding:20px 40px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="font-size:11px;color:#94a3b8;"><strong style="color:#64748b;">ServerSentinel</strong> — Automated Security Platform</td>
          <td align="right" style="font-size:11px;color:#94a3b8;">{{ now()->format('Y') }}</td>
        </tr>
      </table>
      <p style="font-size:10px;color:#cbd5e1;margin-top:8px;margin-bottom:0;">
        This report is confidential and intended solely for the named recipient.
        If you received this in error, please delete it immediately.
      </p>
    </td>
  </tr>

</table>
</td></tr>
</table>
</body>
</html>