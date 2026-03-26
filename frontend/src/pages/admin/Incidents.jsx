import { useState, useEffect, useMemo, useRef } from 'react';
import { Download, Filter, Pencil, Check, X } from 'lucide-react';
import toast from 'react-hot-toast';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import api from '../../api/axios';
import { updateIncidentRootCause } from '../../api/adminApi';
import PaginationCenter from '../../components/PaginationCenter';
import { usePeriodStore } from '../../store/periodStore';

const PAGE_SIZE = 10;

// ─── Rule-based Root Cause Generator ─────────────────────────────────────────
function generateRootCause(incident) {
  const { error_type, http_status_code } = incident;
  const code = http_status_code;

  if (error_type === 'http_error' && code) {
    if (code === 400) return 'The server received a malformed or invalid request, likely due to bad parameters or request formatting issues.';
    if (code === 401) return 'The request was rejected due to missing or invalid authentication credentials.';
    if (code === 403) return 'Access to the resource was denied, possibly due to permission restrictions or IP-based blocking on the server.';
    if (code === 404) return 'The monitored resource was not found on the server. The URL may be incorrect or the resource may have been removed.';
    if (code === 405) return 'The HTTP method used is not allowed by the server for this endpoint.';
    if (code === 408) return 'The server timed out waiting for the request. The client or network may be too slow.';
    if (code === 409) return 'A conflict occurred on the server, usually due to a state mismatch or concurrent modification issue.';
    if (code === 410) return 'The requested resource has been permanently removed from the server.';
    if (code === 429) return 'The service is rate-limiting requests due to excessive traffic. Request throttling or backoff should be applied.';
    if (code >= 400 && code < 500) return `A client-side error occurred (HTTP ${code}). The request may be malformed, unauthorized, or targeting a non-existent resource.`;
    if (code === 500) return 'The server encountered an internal error, likely caused by an unhandled exception or application-side bug.';
    if (code === 501) return 'The server does not support the functionality required to fulfill the request.';
    if (code === 502) return 'The upstream server or proxy returned an invalid response. This is typically caused by a misconfigured gateway or a crashed backend service.';
    if (code === 503) return 'The service is temporarily unavailable, likely due to server overload, resource exhaustion, or scheduled maintenance.';
    if (code === 504) return 'The gateway did not receive a timely response from the upstream server, indicating backend latency or a hanging process.';
    if (code === 505) return 'The server does not support the HTTP protocol version used in the request.';
    if (code >= 500) return `A server-side error occurred (HTTP ${code}). The service failed to process the request due to an internal issue.`;
  }

  if (error_type === 'timeout') return 'The service did not respond within the expected time limit. This is typically caused by high server load, network congestion, or an unresponsive backend process.';
  if (error_type === 'connection') return 'A connection to the server could not be established. The host may be down, unreachable, or actively blocking incoming connections.';
  if (error_type === 'dns') return 'DNS resolution failed for the monitored domain. The domain may be misconfigured, expired, or the DNS server may be unreachable.';
  if (error_type === 'ssl') return 'An SSL/TLS handshake error occurred. The certificate may be expired, self-signed, revoked, or the server may have an incompatible TLS configuration.';

  return 'An unexpected error occurred during monitoring. Further investigation of server logs and network conditions is recommended to determine the root cause.';
}

// ─── Inline Root Cause Editor ─────────────────────────────────────────────────
function RootCauseCell({ incident, onSaved }) {
  const [editing, setEditing] = useState(false);
  const [value, setValue]     = useState(incident.root_cause || '');
  const [saving, setSaving]   = useState(false);
  const inputRef              = useRef(null);

  useEffect(() => {
    if (editing && inputRef.current) inputRef.current.focus();
  }, [editing]);

  useEffect(() => {
    if (!editing) setValue(incident.root_cause || '');
  }, [incident.root_cause, editing]);

  const handleSave = async () => {
    setSaving(true);
    try {
      await updateIncidentRootCause(incident.id, value.trim() || null);
      toast.success('Root cause saved');
      onSaved(incident.id, value.trim() || null);
      setEditing(false);
    } catch {
      toast.error('Failed to save root cause');
    } finally {
      setSaving(false);
    }
  };

  const handleCancel = () => {
    setValue(incident.root_cause || '');
    setEditing(false);
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSave(); }
    if (e.key === 'Escape') handleCancel();
  };

  if (editing) {
    return (
      <div className="flex items-start gap-2 min-w-[200px]">
        <textarea
          ref={inputRef}
          value={value}
          onChange={e => setValue(e.target.value)}
          onKeyDown={handleKeyDown}
          rows={2}
          placeholder="Describe the root cause..."
          className="flex-1 text-sm bg-gray-800 border border-gray-600 rounded-lg px-2 py-1
                     text-white placeholder-gray-500 resize-none outline-none
                     focus:border-green-500 transition"
        />
        <div className="flex flex-col gap-1 pt-1">
          <button onClick={handleSave} disabled={saving}
            className="p-1 rounded bg-green-600 hover:bg-green-500 text-white disabled:opacity-50 transition"
            title="Save">
            <Check size={14} />
          </button>
          <button onClick={handleCancel}
            className="p-1 rounded bg-gray-700 hover:bg-gray-600 text-white transition"
            title="Cancel">
            <X size={14} />
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="group flex items-start gap-2 cursor-pointer min-w-[160px]"
      onClick={() => setEditing(true)} title="Click to edit root cause">
      {incident.root_cause
        ? <span className="text-sm text-gray-200 leading-snug">{incident.root_cause}</span>
        : <span className="text-sm text-gray-600 italic">Add root cause…</span>}
      <Pencil size={13} className="text-gray-600 group-hover:text-green-400 mt-0.5 shrink-0 transition" />
    </div>
  );
}

// ─── Status Timeline Cell ─────────────────────────────────────────────────────
// Every incident ALWAYS shows the OPEN status with its start time.
// When it gets resolved, the RESOLVED status is appended below it with a
// connecting line — so the full lifecycle is always visible in the report.
function StatusTimelineCell({ incident }) {
  const isResolved = incident.status === 'resolved';

  return (
    <div className="flex flex-col gap-0 min-w-[150px]">

      {/* ── OPEN marker — always shown ── */}
      <div className="flex items-start gap-2">
        <div className="flex flex-col items-center">
          <span className="w-2 h-2 rounded-full bg-red-400 mt-1 flex-shrink-0"
            style={{ boxShadow: '0 0 5px #f87171' }} />
          {isResolved && (
            <div className="w-px flex-1 bg-gray-700 mt-0.5" style={{ minHeight: '18px' }} />
          )}
        </div>
        <div className="pb-1">
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold bg-red-500/20 text-red-400">
            OPEN
          </span>
          {incident.started_at && (
            <p className="text-[10px] text-gray-600 mt-0.5 leading-tight">
              {new Date(incident.started_at).toLocaleString()}
            </p>
          )}
        </div>
      </div>

      {/* ── RESOLVED marker — only shown once it's resolved ── */}
      {isResolved && (
        <div className="flex items-start gap-2">
          <div className="flex flex-col items-center">
            <span className="w-2 h-2 rounded-full bg-green-400 mt-1 flex-shrink-0"
              style={{ boxShadow: '0 0 5px #34d399' }} />
          </div>
          <div>
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold bg-green-500/20 text-green-400">
              RESOLVED
            </span>
            {incident.resolved_at && (
              <p className="text-[10px] text-gray-600 mt-0.5 leading-tight">
                {new Date(incident.resolved_at).toLocaleString()}
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────
export default function AdminIncidents() {
  const [incidents, setIncidents]         = useState([]);
  const [loading, setLoading]             = useState(true);
  const [exporting, setExporting]         = useState(false);
  const [statusFilter, setStatusFilter]   = useState('all');
  const [page, setPage]                   = useState(1);

  const { exportPeriod, setPeriod } = usePeriodStore();

  useEffect(() => {
    fetchIncidents();
    const interval = setInterval(fetchIncidents, 5000);
    return () => clearInterval(interval);
  }, []);

  const autoFillRootCauses = async (data) => {
    const missing = data.filter(i => !i.root_cause);
    if (missing.length === 0) return data;

    const results = await Promise.allSettled(
      missing.map(async (incident) => {
        const rootCause = generateRootCause(incident);
        await updateIncidentRootCause(incident.id, rootCause);
        return { id: incident.id, root_cause: rootCause };
      })
    );

    const filled = { ...Object.fromEntries(data.map(i => [i.id, i])) };
    results.forEach(result => {
      if (result.status === 'fulfilled') {
        const { id, root_cause } = result.value;
        if (filled[id]) filled[id] = { ...filled[id], root_cause };
      }
    });

    return Object.values(filled);
  };

  const fetchIncidents = async () => {
    try {
      const res  = await api.get('/admin/incidents');
      const data = res.data.data || [];
      const enriched = await autoFillRootCauses(data);
      setIncidents(enriched);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleRootCauseSaved = (id, rootCause) => {
    setIncidents(prev =>
      prev.map(inc => inc.id === id ? { ...inc, root_cause: rootCause } : inc)
    );
  };

  const getErrorTypeLabel = (errorType) => {
    const labels = {
      http_error: 'HTTP Error',
      timeout:    'Timeout',
      connection: 'Connection Failed',
      dns:        'DNS Failed',
      ssl:        'SSL Error',
      unknown:    'Unknown Error',
    };
    return labels[errorType] || errorType || 'N/A';
  };

  const formatDuration = (incident) => {
    if (incident.status === 'open') return 'Ongoing';
    if (incident.down_duration_seconds) {
      const m = Math.floor(incident.down_duration_seconds / 60);
      const s = incident.down_duration_seconds % 60;
      return `${m}m ${s}s`;
    }
    return 'N/A';
  };

  const formatDurationSecs = (seconds) => {
    if (!seconds) return 'N/A';
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return m > 0 ? `${m}m ${s}s` : `${s}s`;
  };

  const periodLabels = { hour: 'Last Hour', day: 'Last 24 Hours', week: 'Last Week', month: 'Last Month' };
  const reportTitles = { hour: 'Hourly Incident Report', day: 'Daily Incident Report', week: 'Weekly Incident Report', month: 'Monthly Incident Report' };

  // Filter works on current status, but the row still shows full history
  const tableRows = useMemo(() => {
    if (statusFilter === 'all') return incidents;
    return incidents.filter(i => i.status === statusFilter);
  }, [incidents, statusFilter]);

  const totalPages = Math.max(1, Math.ceil(tableRows.length / PAGE_SIZE));
  const safePage   = Math.min(page, totalPages);
  const pageRows   = useMemo(
    () => tableRows.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE),
    [tableRows, safePage]
  );

  useEffect(() => setPage(1), [statusFilter]);
  useEffect(() => { if (page !== safePage) setPage(safePage); }, [safePage]); // eslint-disable-line

  // ─── PDF Export ───────────────────────────────────────────────────────────────
  const exportToPDF = async () => {
    try {
      setExporting(true);
      const res = await api.get(`/admin/export-incidents-pdf?period=${exportPeriod}`);
      const data = res.data.data || [];

      if (data.length === 0) { toast.error('No incidents to export for this period'); return; }

      const doc   = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
      const pageW = doc.internal.pageSize.getWidth();
      const pageH = doc.internal.pageSize.getHeight();
      const now   = new Date();
      const GREEN = [16, 185, 129];
      const BLACK = [0, 0, 0];
      const GRAY  = [100, 100, 100];
      const LGRAY = [243, 244, 246];

      const periodLabel = periodLabels[exportPeriod];
      const reportTitle = reportTitles[exportPeriod];
      const genDate     = now.toLocaleString();

      const resolved    = data.filter(i => i.status === 'resolved');
      const open        = data.filter(i => i.status === 'open');
      const durations   = resolved.filter(i => i.down_duration_seconds).map(i => i.down_duration_seconds);
      const avgRes      = durations.length ? formatDurationSecs(Math.round(durations.reduce((a,b)=>a+b,0)/durations.length)) : 'N/A';
      const longestDown = durations.length ? formatDurationSecs(Math.max(...durations)) : 'N/A';
      const periodSecs  = { hour: 3600, day: 86400, week: 604800, month: 2592000 }[exportPeriod];
      const uptimePct   = ((1 - durations.reduce((a,b)=>a+b,0) / periodSecs) * 100).toFixed(2);
      const uniqueMons  = [...new Set(data.map(i => i.monitor?.name))].length;
      const uniqueUsers = [...new Set(data.map(i => i.monitor?.user?.name))].length;

      const serviceMap = {};
      data.forEach(i => {
        const name = i.monitor?.name || 'Unknown';
        if (!serviceMap[name]) serviceMap[name] = { total:0, resolved:0, open:0, durations:[], user: i.monitor?.user?.name||'N/A' };
        serviceMap[name].total++;
        if (i.status==='resolved') { serviceMap[name].resolved++; if(i.down_duration_seconds) serviceMap[name].durations.push(i.down_duration_seconds); }
        else serviceMap[name].open++;
      });

      const userMap = {};
      data.forEach(i => {
        const name = i.monitor?.user?.name || 'Unknown';
        if (!userMap[name]) userMap[name] = { total:0, resolved:0, open:0 };
        userMap[name].total++;
        if (i.status==='resolved') userMap[name].resolved++; else userMap[name].open++;
      });

      const causeMap = {};
      data.forEach(i => { const l = getErrorTypeLabel(i.error_type); causeMap[l] = (causeMap[l]||0)+1; });

      const mostAffected     = Object.entries(serviceMap).sort((a,b)=>b[1].total-a[1].total)[0]?.[0]||'N/A';
      const mostAffectedUser = Object.entries(userMap).sort((a,b)=>b[1].total-a[1].total)[0]?.[0]||'N/A';
      const totalCauses      = Object.values(causeMap).reduce((a,b)=>a+b,0);

      const addFooter = () => {
        doc.setFontSize(8); doc.setTextColor(...GRAY);
        doc.line(14, pageH-12, pageW-14, pageH-12);
        doc.text('UpTimeBot Admin – System Uptime & Downtime Monitoring', 14, pageH-7);
        doc.text(`Generated: ${genDate}`, pageW-14, pageH-7, { align: 'right' });
      };

      let y = 20;
      const section = (num, title) => {
        y += 4;
        doc.setFontSize(13); doc.setFont('helvetica','bold'); doc.setTextColor(...BLACK);
        doc.text(`${num}. ${title}`, 14, y);
        y += 2;
        doc.setDrawColor(...GREEN); doc.setLineWidth(0.5);
        doc.line(14, y, pageW-14, y);
        y += 6;
      };

      doc.setFillColor(...GREEN);
      doc.rect(0, 0, pageW, 38, 'F');
      doc.setFontSize(20); doc.setFont('helvetica','bold'); doc.setTextColor(255,255,255);
      doc.text(reportTitle, pageW/2, 18, { align:'center' });
      doc.setFontSize(11); doc.setFont('helvetica','normal');
      doc.text(`Period: ${periodLabel}   |   Generated: ${genDate}`, pageW/2, 28, { align:'center' });
      y = 50;

      section(1, 'Executive Summary');
      autoTable(doc, {
        startY: y,
        head: [['Metric','Value']],
        body: [
          ['Total Incidents', data.length],
          ['Open Incidents', open.length],
          ['Resolved Incidents', resolved.length],
          ['Resolution Rate', `${data.length>0?((resolved.length/data.length)*100).toFixed(0):0}%`],
          ['Avg Resolution Time', avgRes],
          ['Longest Downtime', longestDown],
          ['Uptime Estimate', `${uptimePct}%`],
          ['Monitors Affected', uniqueMons],
          ['Users Affected', uniqueUsers],
        ],
        theme: 'grid',
        headStyles: { fillColor:[240,240,240], textColor:BLACK, fontStyle:'bold', fontSize:9 },
        bodyStyles: { fontSize:9, textColor:BLACK },
        alternateRowStyles: { fillColor:LGRAY },
        margin: { left:14, right:14 },
      });

      y = doc.lastAutoTable.finalY + 8;
      section(2, 'Full Incident Log');
      autoTable(doc, {
        startY: y,
        head: [['Monitor','User','Opened At','Resolved At','Status','Cause','Root Cause','Duration']],
        body: data.map(i => [
          i.monitor?.name||'N/A',
          i.monitor?.user?.name||'N/A',
          i.started_at ? new Date(i.started_at).toLocaleString() : '—',
          i.resolved_at ? new Date(i.resolved_at).toLocaleString() : 'Still Open',
          i.status.toUpperCase(),
          getErrorTypeLabel(i.error_type),
          i.root_cause || '—',
          i.status==='open' ? 'Ongoing' : (i.down_duration_seconds ? formatDurationSecs(i.down_duration_seconds) : 'N/A'),
        ]),
        theme: 'grid',
        headStyles: { fillColor:[240,240,240], textColor:BLACK, fontStyle:'bold', fontSize:7.5 },
        bodyStyles: { fontSize:7.5, textColor:BLACK },
        alternateRowStyles: { fillColor:LGRAY },
        margin: { left:14, right:14 },
        columnStyles: { 6: { cellWidth: 35 } },
      });

      y = doc.lastAutoTable.finalY + 8;
      section(3, 'Incident Breakdown by Service');
      autoTable(doc, {
        startY: y,
        head: [['Service','Owner','Total','Resolved','Open','Avg Downtime','Uptime %']],
        body: Object.entries(serviceMap).map(([name, s]) => {
          const avgDown = s.durations.length ? formatDurationSecs(Math.round(s.durations.reduce((a,b)=>a+b,0)/s.durations.length)) : 'N/A';
          const svcUptime = ((1 - s.durations.reduce((a,b)=>a+b,0) / periodSecs) * 100).toFixed(2);
          return [name, s.user, s.total, s.resolved, s.open, avgDown, `${svcUptime}%`];
        }),
        theme: 'grid',
        headStyles: { fillColor:[240,240,240], textColor:BLACK, fontStyle:'bold', fontSize:8.5 },
        bodyStyles: { fontSize:8, textColor:BLACK },
        alternateRowStyles: { fillColor:LGRAY },
        margin: { left:14, right:14 },
      });

      y = doc.lastAutoTable.finalY + 8;
      section(4, 'Incident Breakdown by User');
      autoTable(doc, {
        startY: y,
        head: [['User','Total Incidents','Resolved','Open']],
        body: Object.entries(userMap).sort((a,b)=>b[1].total-a[1].total).map(([name,u])=>[name,u.total,u.resolved,u.open]),
        theme: 'grid',
        headStyles: { fillColor:[240,240,240], textColor:BLACK, fontStyle:'bold', fontSize:9 },
        bodyStyles: { fontSize:9, textColor:BLACK },
        alternateRowStyles: { fillColor:LGRAY },
        margin: { left:14, right:14 },
      });

      y = doc.lastAutoTable.finalY + 8;
      section(5, 'Root Cause Summary');
      autoTable(doc, {
        startY: y,
        head: [['Category','Number of Incidents','Percentage']],
        body: Object.entries(causeMap).sort((a,b)=>b[1]-a[1]).map(([cat,count])=>[cat, count, `${((count/totalCauses)*100).toFixed(1)}%`]),
        theme: 'grid',
        headStyles: { fillColor:[240,240,240], textColor:BLACK, fontStyle:'bold', fontSize:9 },
        bodyStyles: { fontSize:9, textColor:BLACK },
        alternateRowStyles: { fillColor:LGRAY },
        margin: { left:14, right:14 },
      });

      y = doc.lastAutoTable.finalY + 8;
      section(6, 'Key Insights');
      [
        `• ${data.length} total incident(s) during the ${periodLabel.toLowerCase()}.`,
        `• ${resolved.length} resolved — ${data.length>0?((resolved.length/data.length)*100).toFixed(0):0}% resolution rate.`,
        `• Average resolution time: ${avgRes}.`,
        `• Most affected service: ${mostAffected} (owner: ${mostAffectedUser}).`,
        `• Most common root cause: ${Object.entries(causeMap).sort((a,b)=>b[1]-a[1])[0]?.[0]||'N/A'}.`,
        `• Overall system uptime estimate: ${uptimePct}%.`,
        `• ${uniqueUsers} user(s) affected across ${uniqueMons} monitored service(s).`,
      ].forEach(line => { doc.setFontSize(10); doc.setFont('helvetica','normal'); doc.setTextColor(...BLACK); doc.text(line, 14, y); y+=6; });

      y += 4;
      section(7, 'Recommendations');
      ['• Review monitors with recurring open incidents and escalate to respective users.',
       '• Implement automated scaling for services with high downtime rates.',
       '• Set up per-user incident thresholds to trigger automatic notifications.',
       '• Conduct regular load testing before major platform releases.',
      ].forEach(line => { doc.setFontSize(10); doc.setFont('helvetica','normal'); doc.setTextColor(...BLACK); doc.text(line, 14, y); y+=6; });

      y += 6;
      section(8, 'Approval & Sign-off');
      autoTable(doc, {
        startY: y,
        head: [['Role','Name','Date']],
        body: [['Prepared By (Admin)','________________________','____________'],['Reviewed By','________________________','____________'],['Approved By','________________________','____________']],
        theme: 'grid',
        headStyles: { fillColor:[240,240,240], textColor:BLACK, fontStyle:'bold', fontSize:9 },
        bodyStyles: { fontSize:9, textColor:BLACK, minCellHeight:10 },
        margin: { left:14, right:14 },
      });

      addFooter();
      doc.save(`admin-incident-report-${exportPeriod}-${now.toISOString().split('T')[0]}.pdf`);
      toast.success('Admin report exported successfully!');
    } catch (err) {
      toast.error('Failed to export PDF');
      console.error(err);
    } finally {
      setExporting(false);
    }
  };

  // ─── Render ───────────────────────────────────────────────────────────────────
  return (
    <div className="p-8">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold text-white">Incidents</h1>
        <div className="flex items-center gap-3">
          <select value={exportPeriod} onChange={e => setPeriod('exportPeriod', e.target.value)}
            className="px-4 py-2 bg-gray-900 text-white rounded-lg border border-gray-800 outline-none text-sm">
            <option value="hour">Export: Last Hour</option>
            <option value="day">Export: Last 24 Hours</option>
            <option value="week">Export: Last Week</option>
            <option value="month">Export: Last Month</option>
          </select>
          <button onClick={exportToPDF} disabled={exporting}
            className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition disabled:opacity-50">
            <Download size={20} />
            {exporting ? 'Exporting...' : 'Export PDF'}
          </button>
        </div>
      </div>

      {/* Status filter + count badges */}
      <div className="flex items-center gap-4 mb-6">
        <Filter size={20} className="text-gray-400" />
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}
          className="px-4 py-2 bg-gray-900 text-white rounded-lg border border-gray-800 outline-none">
          <option value="all">All Status</option>
          <option value="open">Open</option>
          <option value="resolved">Resolved</option>
        </select>
        <div className="flex gap-2 ml-2">
          <span className="px-3 py-1 rounded-full text-xs font-bold bg-red-500/20 text-red-400">
            {incidents.filter(i => i.status === 'open').length} Open
          </span>
          <span className="px-3 py-1 rounded-full text-xs font-bold bg-green-500/20 text-green-400">
            {incidents.filter(i => i.status === 'resolved').length} Resolved
          </span>
        </div>
      </div>

      <div className="rounded-2xl border border-gray-800 bg-gradient-to-b from-gray-950 to-gray-900 shadow-lg overflow-hidden">
        <div className="max-h-[70vh] overflow-auto">
          <table className="w-full text-left">
            <thead className="sticky top-0 bg-gray-950/95 backdrop-blur border-b border-gray-800">
              <tr className="text-xs uppercase tracking-wider text-gray-400">
                <th className="px-5 py-3">Monitor</th>
                <th className="px-5 py-3">User</th>
                <th className="px-5 py-3">Status</th>
                <th className="px-5 py-3">Cause</th>
                <th className="px-5 py-3">Root Cause</th>
                <th className="px-5 py-3">Started</th>
                <th className="px-5 py-3">Resolved</th>
                <th className="px-5 py-3 text-right">Duration</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td className="px-5 py-6 text-gray-400" colSpan={8}>Loading incidents...</td></tr>
              ) : tableRows.length === 0 ? (
                <tr><td className="px-5 py-6 text-gray-400" colSpan={8}>No incidents found</td></tr>
              ) : pageRows.map(incident => (
                <tr key={incident.id} className="border-b border-gray-900 hover:bg-gray-900/40">
                  <td className="px-5 py-4">
                    <div className="text-white font-semibold">{incident.monitor?.name || 'N/A'}</div>
                    <div className="text-gray-500 text-sm truncate max-w-[200px]">{incident.monitor?.url || '—'}</div>
                  </td>
                  <td className="px-5 py-4">
                    <div className="text-white">{incident.monitor?.user?.name || 'N/A'}</div>
                    <div className="text-xs text-gray-500">{incident.monitor?.user?.email || ''}</div>
                  </td>

                  {/* Status column: always shows OPEN, and appends RESOLVED below when done */}
                  <td className="px-5 py-4">
                    <StatusTimelineCell incident={incident} />
                  </td>

                  <td className="px-5 py-4 text-white text-sm">
                    {getErrorTypeLabel(incident.error_type)}
                    {incident.http_status_code && (
                      <div className="text-xs text-gray-500">HTTP {incident.http_status_code}</div>
                    )}
                  </td>
                  <td className="px-5 py-4 max-w-[220px]">
                    <RootCauseCell incident={incident} onSaved={handleRootCauseSaved} />
                  </td>
                  <td className="px-5 py-4 text-white text-sm">
                    {incident.started_at ? new Date(incident.started_at).toLocaleString() : '—'}
                  </td>
                  <td className="px-5 py-4 text-sm">
                    {incident.resolved_at
                      ? <span className="text-green-400">{new Date(incident.resolved_at).toLocaleString()}</span>
                      : <span className="text-gray-600">—</span>}
                  </td>
                  <td className="px-5 py-4 text-right text-white text-sm font-semibold">
                    {formatDuration(incident)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <PaginationCenter
          page={safePage}
          totalPages={totalPages}
          onPrev={() => setPage(p => Math.max(1, p-1))}
          onNext={() => setPage(p => Math.min(totalPages, p+1))}
        />
      </div>
    </div>
  );
}