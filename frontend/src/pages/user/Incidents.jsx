import { useState, useEffect, useRef, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Download, Filter } from 'lucide-react';
import toast from 'react-hot-toast';
import { getUserIncidents } from '../../api/userApi';
import api from '../../api/axios';
import { usePeriodStore } from '../../store/periodStore';
import PaginationCenter from '../../components/PaginationCenter';

const PAGE_SIZE = 10;

// ─── Status Timeline Cell ─────────────────────────────────────────────────────
// Always shows OPEN with its start time.
// Once resolved, RESOLVED is appended below with a connecting line.
// The row is never replaced — both statuses stay visible for the full history.
function StatusTimelineCell({ incident }) {
  const isResolved = incident.status === 'resolved';
  return (
    <div className="flex flex-col gap-0 min-w-[140px]">
      {/* OPEN — always visible */}
      <div className="flex items-start gap-2">
        <div className="flex flex-col items-center">
          <span
            className="w-2 h-2 rounded-full bg-red-400 mt-1 flex-shrink-0"
            style={{ boxShadow: '0 0 5px #f87171' }}
          />
          {isResolved && (
            <div className="w-px bg-gray-700 mt-0.5" style={{ minHeight: '16px' }} />
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

      {/* RESOLVED — only appears once resolved */}
      {isResolved && (
        <div className="flex items-start gap-2">
          <div className="pt-0.5">
            <span
              className="w-2 h-2 rounded-full bg-green-400 block flex-shrink-0"
              style={{ boxShadow: '0 0 5px #34d399' }}
            />
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

export default function UserIncidents() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [statusFilter, setStatusFilter] = useState('all');
  const [highlightId, setHighlightId] = useState(null);
  const [page, setPage] = useState(1);

  const [searchParams] = useSearchParams();
  const highlightRef = useRef(null);
  const jumpedRef = useRef(false);

  const { exportPeriod, setPeriod } = usePeriodStore();

  useEffect(() => {
    const statusParam = searchParams.get('status');
    if (statusParam === 'open') setStatusFilter('open');
    else if (statusParam === 'resolved') setStatusFilter('resolved');
    else if (statusParam === 'all') setStatusFilter('all');
  }, [searchParams]);

  useEffect(() => {
    const id = searchParams.get('highlight');
    if (id) {
      setHighlightId(Number(id));
      setPeriod('exportPeriod', 'month');
      jumpedRef.current = false;
      const timer = setTimeout(() => setHighlightId(null), 3000);
      return () => clearTimeout(timer);
    }
  }, [searchParams, setPeriod]);

  useEffect(() => {
    fetchIncidents();
    const interval = setInterval(fetchIncidents, 5000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statusFilter]);

  const fetchIncidents = async () => {
    try {
      const monitorId = searchParams.get('monitor');
      const res = await getUserIncidents({
        per_page: 200,
        ...(monitorId && { monitor: monitorId }),
      });
      setIncidents(res.data.data || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const getErrorTypeLabel = (errorType) => {
    const labels = {
      http_error: 'HTTP Error',
      timeout: 'Timeout',
      connection: 'Connection Failed',
      dns: 'DNS Failed',
      ssl: 'SSL Error',
      unknown: 'Unknown Error',
    };
    return labels[errorType] || errorType || 'N/A';
  };

  const formatDurationSecs = (seconds) => {
    if (!seconds) return 'N/A';
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return m > 0 ? `${m}m ${s}s` : `${s}s`;
  };

  const periodLabels = {
    hour: 'Last Hour',
    day: 'Last 24 Hours',
    week: 'Last Week',
    month: 'Last Month',
  };
  const reportTitles = {
    hour: 'Hourly Incident Report',
    day: 'Daily Incident Report',
    week: 'Weekly Incident Report',
    month: 'Monthly Incident Report',
  };

  const getFilteredByPeriod = (items) => {
    const now = new Date();
    const cutoffs = {
      hour: new Date(now - 1 * 60 * 60 * 1000),
      day: new Date(now - 24 * 60 * 60 * 1000),
      week: new Date(now - 7 * 24 * 60 * 60 * 1000),
      month: new Date(now - 30 * 24 * 60 * 60 * 1000),
    };
    return items.filter((i) => new Date(i.started_at) >= cutoffs[exportPeriod]);
  };

  // ─── PDF Export (Lazy-load jsPDF + autotable) ────────────────────────────────
  const exportToPDF = async () => {
    try {
      setExporting(true);

      // ✅ Load heavy libraries only when user clicks Export
      const [{ default: jsPDF }, { default: autoTable }] = await Promise.all([
        import('jspdf'),
        import('jspdf-autotable'),
      ]);

      const res = await api.get(`/user/export-incidents-pdf?period=${exportPeriod}`);
      const data = res.data.data || [];

      if (data.length === 0) {
        toast.error('No incidents to export for this period');
        return;
      }

      const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
      const pageW = doc.internal.pageSize.getWidth();
      const pageH = doc.internal.pageSize.getHeight();
      const now = new Date();
      const GREEN = [16, 185, 129];
      const BLACK = [0, 0, 0];
      const GRAY = [100, 100, 100];
      const LGRAY = [243, 244, 246];

      const periodLabel = periodLabels[exportPeriod];
      const reportTitle = reportTitles[exportPeriod];
      const genDate = now.toLocaleString();

      const resolved = data.filter((i) => i.status === 'resolved');
      const open = data.filter((i) => i.status === 'open');
      const durations = resolved.filter((i) => i.down_duration_seconds).map((i) => i.down_duration_seconds);

      const avgRes = durations.length
        ? formatDurationSecs(Math.round(durations.reduce((a, b) => a + b, 0) / durations.length))
        : 'N/A';

      const longestDown = durations.length ? formatDurationSecs(Math.max(...durations)) : 'N/A';

      const periodSecs = { hour: 3600, day: 86400, week: 604800, month: 2592000 }[exportPeriod];
      const totalDown = durations.reduce((a, b) => a + b, 0);
      const uptimePct = ((1 - totalDown / periodSecs) * 100).toFixed(2);
      const uniqueMons = [...new Set(data.map((i) => i.monitor?.name))].length;

      const serviceMap = {};
      data.forEach((i) => {
        const name = i.monitor?.name || 'Unknown';
        if (!serviceMap[name]) serviceMap[name] = { total: 0, resolved: 0, open: 0, durations: [] };
        serviceMap[name].total++;
        if (i.status === 'resolved') {
          serviceMap[name].resolved++;
          if (i.down_duration_seconds) serviceMap[name].durations.push(i.down_duration_seconds);
        } else {
          serviceMap[name].open++;
        }
      });

      const causeMap = {};
      data.forEach((i) => {
        const label = getErrorTypeLabel(i.error_type);
        causeMap[label] = (causeMap[label] || 0) + 1;
      });

      const mostAffected =
        Object.entries(serviceMap).sort((a, b) => b[1].total - a[1].total)[0]?.[0] || 'N/A';

      const totalCauses = Object.values(causeMap).reduce((a, b) => a + b, 0);

      const addFooter = () => {
        doc.setFontSize(8);
        doc.setTextColor(...GRAY);
        doc.line(14, pageH - 12, pageW - 14, pageH - 12);
        doc.text('UpTimeBot – System Uptime & Downtime Monitoring', 14, pageH - 7);
        doc.text(`Generated: ${genDate}`, pageW - 14, pageH - 7, { align: 'right' });
      };

      let y = 20;
      const section = (num, title) => {
        y += 4;
        doc.setFontSize(13);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...BLACK);
        doc.text(`${num}. ${title}`, 14, y);
        y += 2;
        doc.setDrawColor(...GREEN);
        doc.setLineWidth(0.5);
        doc.line(14, y, pageW - 14, y);
        y += 6;
      };

      // Cover
      doc.setFillColor(...GREEN);
      doc.rect(0, 0, pageW, 38, 'F');
      doc.setFontSize(20);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(255, 255, 255);
      doc.text(reportTitle, pageW / 2, 18, { align: 'center' });
      doc.setFontSize(11);
      doc.setFont('helvetica', 'normal');
      doc.text(`Period: ${periodLabel}   |   Generated: ${genDate}`, pageW / 2, 28, { align: 'center' });
      y = 50;

      section(1, 'Executive Summary');
      autoTable(doc, {
        startY: y,
        head: [['Metric', 'Value']],
        body: [
          ['Total Incidents', data.length],
          ['Open Incidents', open.length],
          ['Resolved Incidents', resolved.length],
          ['Resolution Rate', `${data.length > 0 ? ((resolved.length / data.length) * 100).toFixed(0) : 0}%`],
          ['Avg Resolution Time', avgRes],
          ['Longest Downtime', longestDown],
          ['Uptime Estimate', `${uptimePct}%`],
          ['Monitors Affected', uniqueMons],
        ],
        theme: 'grid',
        headStyles: { fillColor: [240, 240, 240], textColor: BLACK, fontStyle: 'bold', fontSize: 9 },
        bodyStyles: { fontSize: 9, textColor: BLACK },
        alternateRowStyles: { fillColor: LGRAY },
        margin: { left: 14, right: 14 },
      });

      y = doc.lastAutoTable.finalY + 8;
      section(2, 'Full Incident Log');
      autoTable(doc, {
        startY: y,
        head: [['Monitor', 'Opened At', 'Resolved At', 'Status', 'Cause', 'Root Cause', 'Duration']],
        body: data.map((i) => [
          i.monitor?.name || 'N/A',
          i.started_at ? new Date(i.started_at).toLocaleString() : '—',
          i.resolved_at ? new Date(i.resolved_at).toLocaleString() : 'Still Open',
          i.status.toUpperCase(),
          getErrorTypeLabel(i.error_type),
          i.root_cause || '—',
          i.status === 'open' ? 'Ongoing' : (i.down_duration_seconds ? formatDurationSecs(i.down_duration_seconds) : 'N/A'),
        ]),
        theme: 'grid',
        headStyles: { fillColor: [240, 240, 240], textColor: BLACK, fontStyle: 'bold', fontSize: 8 },
        bodyStyles: { fontSize: 8, textColor: BLACK },
        alternateRowStyles: { fillColor: LGRAY },
        margin: { left: 14, right: 14 },
        columnStyles: { 5: { cellWidth: 38 } },
      });

      y = doc.lastAutoTable.finalY + 8;
      section(3, 'Incident Breakdown by Service');
      autoTable(doc, {
        startY: y,
        head: [['Service', 'Total', 'Resolved', 'Open', 'Avg Downtime', 'Uptime %']],
        body: Object.entries(serviceMap).map(([name, s]) => {
          const avgDown = s.durations.length
            ? formatDurationSecs(Math.round(s.durations.reduce((a, b) => a + b, 0) / s.durations.length))
            : 'N/A';
          const svcUptime = ((1 - s.durations.reduce((a, b) => a + b, 0) / periodSecs) * 100).toFixed(2);
          return [name, s.total, s.resolved, s.open, avgDown, `${svcUptime}%`];
        }),
        theme: 'grid',
        headStyles: { fillColor: [240, 240, 240], textColor: BLACK, fontStyle: 'bold', fontSize: 9 },
        bodyStyles: { fontSize: 8.5, textColor: BLACK },
        alternateRowStyles: { fillColor: LGRAY },
        margin: { left: 14, right: 14 },
      });

      y = doc.lastAutoTable.finalY + 8;
      section(4, 'Root Cause Summary');
      autoTable(doc, {
        startY: y,
        head: [['Category', 'Number of Incidents', 'Percentage']],
        body: Object.entries(causeMap)
          .sort((a, b) => b[1] - a[1])
          .map(([cat, count]) => [cat, count, `${((count / totalCauses) * 100).toFixed(1)}%`]),
        theme: 'grid',
        headStyles: { fillColor: [240, 240, 240], textColor: BLACK, fontStyle: 'bold', fontSize: 9 },
        bodyStyles: { fontSize: 9, textColor: BLACK },
        alternateRowStyles: { fillColor: LGRAY },
        margin: { left: 14, right: 14 },
      });

      y = doc.lastAutoTable.finalY + 8;
      section(5, 'Key Insights');
      doc.setFontSize(10);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(...BLACK);
      [
        `• ${data.length} total incident(s) during the ${periodLabel.toLowerCase()}.`,
        `• ${resolved.length} resolved — ${data.length > 0 ? ((resolved.length / data.length) * 100).toFixed(0) : 0}% resolution rate.`,
        `• Average resolution time: ${avgRes}.`,
        `• Most affected service: ${mostAffected}.`,
        `• Most common failure cause: ${Object.entries(causeMap).sort((a, b) => b[1] - a[1])[0]?.[0] || 'N/A'}.`,
        `• Overall uptime estimate: ${uptimePct}%.`,
      ].forEach((line) => {
        doc.text(line, 14, y);
        y += 6;
      });

      y += 4;
      section(6, 'Recommendations');
      doc.setFontSize(10);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(...BLACK);
      [
        '• Review monitors with recurring open incidents and contact your administrator.',
        '• Ensure SSL certificates and DNS records are kept up to date.',
        '• Consider increasing server resources for monitors with frequent timeouts.',
        '• Schedule regular maintenance windows to minimize unplanned downtime.',
      ].forEach((line) => {
        doc.text(line, 14, y);
        y += 6;
      });

      y += 4;
      section(7, 'Approval & Sign-off');
      autoTable(doc, {
        startY: y,
        head: [['Role', 'Name', 'Date']],
        body: [
          ['Prepared By', '________________________', '____________'],
          ['Reviewed By', '________________________', '____________'],
          ['Approved By', '________________________', '____________'],
        ],
        theme: 'grid',
        headStyles: { fillColor: [240, 240, 240], textColor: BLACK, fontStyle: 'bold', fontSize: 9 },
        bodyStyles: { fontSize: 9, textColor: BLACK, minCellHeight: 10 },
        margin: { left: 14, right: 14 },
      });

      addFooter();
      doc.save(`incident-report-${exportPeriod}-${now.toISOString().split('T')[0]}.pdf`);
      toast.success('Report exported successfully!');
    } catch (err) {
      toast.error('Failed to export PDF');
      console.error(err);
    } finally {
      setExporting(false);
    }
  };

  // ─── Filtering & Pagination ───────────────────────────────────────────────────
  const monitorId = searchParams.get('monitor');

  const filtered = useMemo(() => {
    const base =
      statusFilter === 'all' ? incidents : incidents.filter((i) => i.status === statusFilter);
    return base.slice().sort((a, b) => {
      const ta = a.started_at ? new Date(a.started_at).getTime() : 0;
      const tb = b.started_at ? new Date(b.started_at).getTime() : 0;
      return tb - ta;
    });
  }, [incidents, statusFilter]);

  const periodFiltered = useMemo(() => getFilteredByPeriod(filtered), [filtered, exportPeriod]);

  useEffect(() => setPage(1), [statusFilter, exportPeriod, monitorId]);

  useEffect(() => {
    if (!highlightId) return;
    if (jumpedRef.current) return;
    const idx = periodFiltered.findIndex((i) => i.id === highlightId);
    if (idx === -1) return;
    jumpedRef.current = true;
    setPage(Math.floor(idx / PAGE_SIZE) + 1);
  }, [highlightId, periodFiltered]);

  const totalPages = Math.max(1, Math.ceil(periodFiltered.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const pageRows = periodFiltered.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  useEffect(() => {
    if (highlightId && highlightRef.current) {
      setTimeout(() => highlightRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 250);
    }
  }, [highlightId, safePage]);

  // ─── Render ───────────────────────────────────────────────────────────────────
  return (
    <div className="p-8">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold text-white">My Incidents</h1>
          {monitorId && incidents.length > 0 && (
            <p className="text-sm text-green-400 mt-1">
              📍 Filtered by: <span className="font-bold">{incidents[0]?.monitor?.name}</span>
            </p>
          )}
        </div>

        <div className="flex items-center gap-3">
          <select
            value={exportPeriod}
            onChange={(e) => setPeriod('exportPeriod', e.target.value)}
            className="px-4 py-2 bg-gray-900 text-white rounded-lg border border-gray-800 outline-none text-sm"
          >
            <option value="hour">Last Hour</option>
            <option value="day">Last 24 Hours</option>
            <option value="week">Last Week</option>
            <option value="month">Last Month</option>
          </select>

          <button
            onClick={exportToPDF}
            disabled={exporting}
            className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition disabled:opacity-50"
          >
            <Download size={20} />
            {exporting ? 'Exporting...' : 'Export PDF'}
          </button>
        </div>
      </div>

      {/* Filter row */}
      <div className="flex items-center gap-4 mb-4">
        <Filter size={20} className="text-gray-400" />
        <select
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value);
            setPage(1);
          }}
          className="px-4 py-2 bg-gray-900 text-white rounded-lg border border-gray-800 outline-none"
        >
          <option value="all">All Status</option>
          <option value="open">Open</option>
          <option value="resolved">Resolved</option>
        </select>

        <div className="flex gap-2 ml-2">
          <span className="px-3 py-1 rounded-full text-xs font-bold bg-red-500/20 text-red-400">
            {incidents.filter((i) => i.status === 'open').length} Open
          </span>
          <span className="px-3 py-1 rounded-full text-xs font-bold bg-green-500/20 text-green-400">
            {incidents.filter((i) => i.status === 'resolved').length} Resolved
          </span>
        </div>

        {statusFilter !== 'all' && (
          <span
            className={`text-xs px-3 py-1 rounded-full font-medium ${
              statusFilter === 'open'
                ? 'bg-red-500/20 text-red-400'
                : 'bg-green-500/20 text-green-400'
            }`}
          >
            Showing: {statusFilter === 'open' ? 'Active Incidents' : 'Resolved Incidents'}
          </span>
        )}
      </div>

      <p className="text-gray-400 text-sm mb-4">
        Showing {periodFiltered.length} of {incidents.length} incidents ({periodLabels[exportPeriod]})
      </p>

      {loading && incidents.length === 0 ? (
        <div className="text-center py-12 text-gray-400">Loading incidents...</div>
      ) : periodFiltered.length === 0 ? (
        <div className="text-center py-12 text-gray-400">No incidents found for this period</div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-800 border-b border-gray-700">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Monitor
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Cause
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Root Cause
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Started
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Resolved
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Duration
                </th>
              </tr>
            </thead>

            <tbody className="divide-y divide-gray-800">
              {pageRows.map((incident) => {
                const isHighlighted = incident.id === highlightId;
                return (
                  <tr
                    key={incident.id}
                    ref={isHighlighted ? highlightRef : null}
                    className={`transition-all duration-700 ${
                      isHighlighted
                        ? 'bg-yellow-500/10 ring-2 ring-inset ring-yellow-400/50'
                        : 'hover:bg-gray-800/50'
                    }`}
                  >
                    {/* Monitor */}
                    <td className="px-4 py-3">
                      {isHighlighted && (
                        <span className="inline-block text-xs font-bold text-yellow-400 bg-yellow-500/20 px-2 py-0.5 rounded-full animate-pulse mb-1">
                          📍 From Dashboard
                        </span>
                      )}
                      <div className={`font-medium ${isHighlighted ? 'text-yellow-300' : 'text-white'}`}>
                        {incident.monitor?.name || 'N/A'}
                      </div>
                      <div className="text-xs text-gray-500 truncate max-w-xs">{incident.monitor?.url}</div>
                    </td>

                    {/* Status */}
                    <td className="px-4 py-3">
                      <StatusTimelineCell incident={incident} />
                    </td>

                    {/* Cause */}
                    <td className="px-4 py-3 text-white text-sm">
                      {getErrorTypeLabel(incident.error_type)}
                    </td>

                    {/* Root Cause */}
                    <td className="px-4 py-3 max-w-[200px]">
                      {incident.root_cause ? (
                        <span className="text-sm text-gray-200 leading-snug">{incident.root_cause}</span>
                      ) : (
                        <span className="text-sm text-gray-600 italic">—</span>
                      )}
                    </td>

                    {/* Started */}
                    <td className="px-4 py-3 text-white text-sm">
                      {new Date(incident.started_at).toLocaleString()}
                    </td>

                    {/* Resolved */}
                    <td className="px-4 py-3 text-sm">
                      {incident.resolved_at ? (
                        <span className="text-green-400">{new Date(incident.resolved_at).toLocaleString()}</span>
                      ) : (
                        <span className="text-gray-500">—</span>
                      )}
                    </td>

                    {/* Duration */}
                    <td className="px-4 py-3 text-white text-sm">
                      {incident.down_duration_seconds
                        ? formatDurationSecs(incident.down_duration_seconds)
                        : incident.status === 'open'
                        ? 'Ongoing'
                        : 'N/A'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          <PaginationCenter
            page={safePage}
            totalPages={totalPages}
            onPrev={() => setPage((p) => Math.max(1, p - 1))}
            onNext={() => setPage((p) => Math.min(totalPages, p + 1))}
          />
        </div>
      )}
    </div>
  );
}