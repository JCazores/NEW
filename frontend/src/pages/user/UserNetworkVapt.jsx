import { useState, useEffect, useRef, useCallback } from 'react';
import {
  Network, Play, Download, Filter,
  AlertTriangle, ShieldAlert, Shield, ShieldCheck,
  ChevronDown, ChevronUp, Terminal, CheckCircle2,
  Clock, AlertCircle, Lock, Loader2, XCircle, Wifi,
  Activity, Eye, EyeOff, Radio,
  Target, Cpu, TrendingUp
} from 'lucide-react';
import axios from '../../api/axios';
import toast from 'react-hot-toast';

// ─── CVE Display Block ────────────────────────────────────────────────────────
// CVE IDs come directly from the backend (NvdService live lookup).
// The frontend just displays whatever cve_id the API returns — no hardcoding.
function CveIdBlock({ vuln }) {
  const [copied, setCopied] = useState(null);
  const cveId = vuln.cve_id ?? null;

  const copy = id => {
    navigator.clipboard.writeText(id).then(() => {
      setCopied(id);
      setTimeout(() => setCopied(null), 2000);
    });
  };

  return (
    <div className="bg-gray-800/40 border border-gray-700/50 rounded-xl px-4 py-3 space-y-3">
      <div>
        <p className="text-gray-500 text-[10px] uppercase tracking-widest font-medium mb-2">
          CVE Identifier — search on{' '}
          <a href={`https://nvd.nist.gov/vuln/detail/${cveId}`} target="_blank" rel="noopener noreferrer"
            className="text-indigo-400 hover:text-indigo-300 underline transition">NVD</a>
          {' '}or Google
        </p>
        {cveId ? (
          <button onClick={() => copy(cveId)} title="Click to copy"
            className={`font-mono text-sm font-bold px-3 py-1.5 rounded-lg border transition ${
              copied === cveId
                ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/25'
                : 'text-indigo-300 bg-indigo-500/10 border-indigo-500/25 hover:bg-indigo-500/20 hover:border-indigo-400/40'
            }`}>
            {copied === cveId ? '✓ ' : ''}{cveId}
          </button>
        ) : (
          <span className="text-gray-600 text-xs">No CVE identifier — run a new scan to detect.</span>
        )}
      </div>
      {vuln.description && (
        <div className="border-t border-gray-700/50 pt-3">
          <p className="text-gray-500 text-[10px] uppercase tracking-widest font-medium mb-1.5">Description</p>
          <p className="text-gray-300 text-sm leading-relaxed">{vuln.description}</p>
        </div>
      )}
    </div>
  );
}

// ─── Constants ────────────────────────────────────────────────────────────────
const POLL_MS  = 1000;
const SYNC_MS  = 3000;
const CACHE_KEY  = 'vapt_scan_cache';
const TERMS_KEY  = 'vapt_open_terms';

const SEVERITY = {
  critical: { color: 'text-red-400',    bg: 'bg-red-500/10',    border: 'border-red-500/30',    label: 'Critical', dot: 'bg-red-400'    },
  high:     { color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30', label: 'High',     dot: 'bg-orange-400' },
  medium:   { color: 'text-amber-400',  bg: 'bg-amber-500/10',  border: 'border-amber-500/30',  label: 'Medium',   dot: 'bg-amber-400'  },
  low:      { color: 'text-sky-400',    bg: 'bg-sky-500/10',    border: 'border-sky-500/30',    label: 'Low',      dot: 'bg-sky-400'    },
};

// Single unified scan type — most comprehensive
const SCAN_TYPE = 'vuln';

const STAGES_VULN = [
  { key: 'queued',    label: 'Queued',      short: 'Q'  },
  { key: 'init',      label: 'Init',        short: 'I'  },
  { key: 'discovery', label: 'Discovery',   short: 'D'  },
  { key: 'port',      label: 'Port Scan',   short: 'PS' },
  { key: 'scripts',   label: 'NSE Scripts', short: 'NS' },
  { key: 'analysis',  label: 'Analysis',    short: 'A'  },
  { key: 'saving',    label: 'Saving',      short: 'S'  },
  { key: 'done',      label: 'Complete',    short: '✓'  },
];

function progressToStageIndex(progress, status) {
  if (status === 'done') return STAGES_VULN.length - 1;
  if (status === 'failed') return -1;
  if (status === 'queued' || progress == null || Number(progress) <= 0) return 0;
  const p = Number(progress);
  if (p <= 14) return 1;
  if (p <= 24) return 2;
  if (p <= 39) return 3;
  if (p <= 74) return 4;
  if (p <= 92) return 5;
  if (p <= 99) return 6;
  return 7;
}

// ─── Skeleton loaders ─────────────────────────────────────────────────────────
function normalizePhaseLog(phaseLog) {
  if (!phaseLog) return [];
  if (Array.isArray(phaseLog)) return phaseLog;
  if (typeof phaseLog === 'string') {
    try {
      const parsed = JSON.parse(phaseLog);
      if (Array.isArray(parsed)) return parsed;
      if (parsed && typeof parsed === 'object') return Object.values(parsed);
      return [];
    } catch { return []; }
  }
  if (typeof phaseLog === 'object') return Object.values(phaseLog);
  return [];
}

function normalizeScan(scan) {
  return {
    ...scan,
    phase_log: normalizePhaseLog(scan?.phase_log),
    progress:  scan?.progress != null ? Number(scan.progress) : 0,
  };
}

// ─── Cache helpers ────────────────────────────────────────────────────────────
function readCache() {
  try { const raw = localStorage.getItem(CACHE_KEY); return raw ? JSON.parse(raw) : null; }
  catch { return null; }
}
function writeCache(scans, vulns) {
  try { localStorage.setItem(CACHE_KEY, JSON.stringify({ scans, vulns, ts: Date.now() })); } catch {}
}
function readOpenTerms() {
  try { const raw = localStorage.getItem(TERMS_KEY); return raw ? JSON.parse(raw) : {}; }
  catch { return {}; }
}
function writeOpenTerms(terms) {
  try { localStorage.setItem(TERMS_KEY, JSON.stringify(terms)); } catch {}
}

// ─── Elapsed hook ─────────────────────────────────────────────────────────────
function useElapsed(startDate) {
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    const start = new Date(startDate).getTime();
    if (Number.isNaN(start)) { setElapsed(0); return; }
    const tick = () => setElapsed(Math.floor((Date.now() - start) / 1000));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [startDate]);
  return elapsed;
}

function formatElapsed(secs) {
  const s = Math.max(0, Number(secs) || 0);
  const m = Math.floor(s / 60);
  return m > 0 ? `${m}m ${String(s % 60).padStart(2, '0')}s` : `${s % 60}s`;
}

// ─── Skeleton loaders ─────────────────────────────────────────────────────────
function SkeletonRow() {
  return (
    <div className="px-5 py-4 flex items-center gap-3 animate-pulse">
      <div className="w-16 h-5 bg-gray-800 rounded-md" />
      <div className="w-28 h-4 bg-gray-800 rounded-md" />
      <div className="w-20 h-3 bg-gray-800/60 rounded-md" />
      <div className="ml-auto flex gap-2">
        <div className="w-10 h-5 bg-gray-800 rounded-md" />
        <div className="w-14 h-5 bg-gray-800 rounded-md" />
      </div>
    </div>
  );
}

function SkeletonStatCard() {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 flex items-center gap-3 animate-pulse">
      <div className="w-10 h-10 rounded-xl bg-gray-800" />
      <div className="space-y-2">
        <div className="w-12 h-2.5 bg-gray-800 rounded" />
        <div className="w-8 h-6 bg-gray-800 rounded" />
      </div>
    </div>
  );
}

// ─── Stage Pipeline ───────────────────────────────────────────────────────────
function StagePipeline({ scan }) {
  const isFailed = scan.status === 'failed';
  const stageIdx = progressToStageIndex(scan.progress, scan.status);
  const failedAt = isFailed ? Math.max(0, progressToStageIndex(scan.progress, 'running')) : -1;

  return (
    <div className="flex items-center gap-0">
      {STAGES_VULN.map((stage, i) => {
        const isComplete = !isFailed && i < stageIdx;
        const isActive   = !isFailed && i === stageIdx;
        const isError    = isFailed && i === failedAt;

        return (
          <div key={stage.key} className="flex items-center flex-1 min-w-0">
            <div className="flex flex-col items-center flex-shrink-0">
              <div className={`w-6 h-6 rounded-full flex items-center justify-center text-[9px] font-bold border-2 transition-all duration-500 ${
                isComplete ? 'bg-emerald-500/20 border-emerald-500 text-emerald-400'
                : isActive  ? 'bg-cyan-500/20 border-cyan-400 text-cyan-300 shadow-[0_0_8px_rgba(6,182,212,0.4)]'
                : isError   ? 'bg-red-500/20 border-red-500 text-red-400'
                :             'bg-gray-800 border-gray-700 text-gray-600'
              }`}>
                {isActive   ? <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                : isComplete ? <CheckCircle2 size={10} />
                : isError    ? <XCircle size={10} />
                :              stage.short}
              </div>
              <span className={`text-[9px] mt-0.5 font-medium hidden md:block truncate max-w-[52px] text-center leading-tight ${
                isComplete ? 'text-emerald-500' : isActive ? 'text-cyan-400' : isError ? 'text-red-400' : 'text-gray-700'
              }`}>{stage.label}</span>
            </div>
            {i < STAGES_VULN.length - 1 && (
              <div className={`flex-1 h-px mx-0.5 transition-all duration-700 ${
                isComplete ? 'bg-emerald-500/60' : isActive ? 'bg-gradient-to-r from-cyan-500/60 to-gray-700' : 'bg-gray-800'
              }`} />
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─── Live Scan Terminal ───────────────────────────────────────────────────────
function ScanTerminal({ scan, compact = false }) {
  const logRef = useRef(null);
  const log    = normalizePhaseLog(scan.phase_log);
  const elapsed = useElapsed(scan.created_at);
  const isStuck = elapsed > 600; // 10 min

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [log.length]);

  return (
    <div className={`bg-[#080c10] border border-gray-700/50 rounded-xl overflow-hidden ${compact ? '' : 'mt-3'}`}>
      {/* Terminal title bar */}
      <div className="flex items-center gap-2 px-3 py-2 bg-gray-900/80 border-b border-gray-800">
        <div className="flex gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500/60" />
          <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/60" />
          <span className="w-2.5 h-2.5 rounded-full bg-green-500/60" />
        </div>
        <span className="text-gray-500 text-[11px] font-mono ml-1 truncate">nmap — {scan.target}</span>
        <div className="ml-auto flex items-center gap-2 flex-shrink-0">
          {scan.status === 'running' || scan.status === 'queued' ? (
            <span className={`text-[11px] font-mono flex items-center gap-1.5 ${isStuck ? 'text-red-400' : 'text-cyan-400'}`}>
              <Radio size={9} className={isStuck ? '' : 'animate-pulse'} />
              {formatElapsed(elapsed)}
              {isStuck && <span className="text-red-400 ml-1">⚠ stuck?</span>}
            </span>
          ) : scan.status === 'failed' ? (
            <span className="text-[11px] text-red-400 font-mono flex items-center gap-1"><XCircle size={9} /> failed</span>
          ) : (
            <span className="text-[11px] text-emerald-400 font-mono">✓ {formatElapsed(elapsed)}</span>
          )}
        </div>
      </div>

      {/* Progress bar */}
      <div className="h-0.5 bg-gray-900">
        <div className={`h-full transition-all duration-700 ${
          scan.status === 'failed' ? 'bg-red-500' : scan.status === 'done' ? 'bg-emerald-500' : 'bg-cyan-500'
        }`} style={{ width: `${scan.progress ?? 0}%` }} />
      </div>

      {/* Log lines */}
      <div ref={logRef} className={`p-3 space-y-0.5 overflow-y-auto font-mono text-[11px] ${compact ? 'max-h-32' : 'max-h-48'}`}>
        {log.length === 0 ? (
          <p className="text-gray-700 italic">Waiting for scanner...</p>
        ) : (
          log.map((entry, i) => (
            <div key={i} className="flex gap-2">
              <span className="text-gray-700 flex-shrink-0 w-12 text-right">{entry?.time ?? '--:--'}</span>
              <span className={`flex-shrink-0 font-bold ${
                entry?.progress === 100 && scan.status === 'done' ? 'text-emerald-400'
                : entry?.phase === 'Failed' ? 'text-red-400'
                : 'text-cyan-500'
              }`}>[{entry?.phase ?? 'Log'}]</span>
              <span className="text-gray-400 break-all">{entry?.detail ?? 'No details available'}</span>
            </div>
          ))
        )}
        {(scan.status === 'running' || scan.status === 'queued') && (
          <div className="flex gap-2 mt-0.5">
            <span className="text-gray-700 w-12 text-right">—</span>
            <span className="text-cyan-400 animate-pulse">▌</span>
          </div>
        )}
      </div>

      {(scan.status === 'running' || scan.status === 'queued') && scan.phase && (
        <div className="px-3 py-1.5 border-t border-gray-800/80 flex items-center gap-2 text-[11px] bg-gray-900/40">
          <Loader2 size={10} className="text-cyan-400 animate-spin flex-shrink-0" />
          <span className="text-cyan-400 font-semibold font-mono">{scan.phase}</span>
          {scan.progress != null && <span className="text-gray-600 ml-auto font-mono">{scan.progress}%</span>}
        </div>
      )}
      {scan.status === 'failed' && scan.error_message && (
        <div className="px-3 py-1.5 border-t border-red-900/40 bg-red-500/5 text-[11px] text-red-400 font-mono flex items-center gap-2">
          <XCircle size={10} /> {scan.error_message}
        </div>
      )}
    </div>
  );
}

// ─── Active Scan Card ─────────────────────────────────────────────────────────
function ActiveScanCard({ scan, onToggleTerm, showTerm }) {
  const elapsed = useElapsed(scan.created_at);
  const isStuck = elapsed > 600;

  const statusMeta = {
    running: { glow: 'border-cyan-500/40 shadow-[0_0_24px_rgba(6,182,212,0.07)]', dot: 'bg-cyan-400 animate-pulse', label: 'Running', labelColor: 'text-cyan-400' },
    queued:  { glow: 'border-amber-500/30 shadow-[0_0_24px_rgba(245,158,11,0.05)]', dot: 'bg-amber-400 animate-pulse', label: 'Queued', labelColor: 'text-amber-400' },
    failed:  { glow: 'border-red-500/40', dot: 'bg-red-400', label: 'Failed', labelColor: 'text-red-400' },
    done:    { glow: 'border-emerald-500/30', dot: 'bg-emerald-400', label: 'Done', labelColor: 'text-emerald-400' },
  }[scan.status] ?? { glow: 'border-gray-800', dot: 'bg-gray-500', label: 'Unknown', labelColor: 'text-gray-400' };

  return (
    <div className={`bg-gray-900 border rounded-2xl overflow-hidden transition-all duration-300 ${statusMeta.glow}`}>
      {/* Header */}
      <div className="px-4 py-3 flex items-center gap-3 border-b border-gray-800/60">
        <div className={`w-2 h-2 rounded-full flex-shrink-0 ${statusMeta.dot}`} />
        <div className="flex-1 min-w-0">
          <p className="text-white text-sm font-mono font-semibold truncate">{scan.target}</p>
          <p className={`text-xs ${statusMeta.labelColor}`}>
            {statusMeta.label}
            {scan.progress > 0 && scan.status === 'running' && ` · ${scan.progress}%`}
            {isStuck && <span className="text-orange-400 ml-1">⚠ may be stuck</span>}
          </p>
        </div>
        <span className="text-gray-600 text-xs font-mono flex-shrink-0">{formatElapsed(elapsed)}</span>
        <button
          onClick={onToggleTerm}
          className={`p-1.5 rounded-lg transition text-[11px] ${showTerm ? 'bg-cyan-500/20 text-cyan-400' : 'bg-gray-800 text-gray-500 hover:text-gray-300'}`}
          title={showTerm ? 'Hide logs' : 'Show logs'}
        >
          {showTerm ? <EyeOff size={12} /> : <Eye size={12} />}
        </button>
      </div>

      {/* Stage pipeline */}
      <div className="px-4 pt-3 pb-2">
        <StagePipeline scan={scan} />
      </div>

      {/* Status message */}
      <div className="px-4 pb-3">
        {scan.status === 'queued' && (
          <p className="text-amber-400/80 text-xs flex items-center gap-1.5 mt-1">
            <Loader2 size={10} className="animate-spin" /> Waiting in queue...
          </p>
        )}
        {scan.status === 'running' && scan.phase && (
          <p className="text-cyan-400/80 text-xs flex items-center gap-1.5 mt-1">
            <Activity size={10} />
            <span className="font-mono">{scan.phase}</span>
          </p>
        )}
        {scan.status === 'failed' && (
          <p className="text-red-400/80 text-xs flex items-center gap-1.5 mt-1">
            <XCircle size={10} /> {scan.error_message ?? 'Scan failed — check logs for details'}
          </p>
        )}
      </div>

      {showTerm && (
        <div className="px-4 pb-4">
          <ScanTerminal scan={scan} compact />
        </div>
      )}
    </div>
  );
}

// ─── Severity Badge ───────────────────────────────────────────────────────────
function SeverityBadge({ severity }) {
  const m = SEVERITY[severity] ?? SEVERITY.low;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold ${m.color} ${m.bg} border ${m.border}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${m.dot}`} />
      {m.label}
    </span>
  );
}

function StatusBadge({ status }) {
  const map = {
    done:    { cls: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30', label: 'Done',    icon: <CheckCircle2 size={9} /> },
    running: { cls: 'text-cyan-300 bg-cyan-500/15 border-cyan-400/30',          label: 'Running', icon: <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" /> },
    queued:  { cls: 'text-amber-300 bg-amber-500/15 border-amber-400/30',       label: 'Queued',  icon: <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" /> },
    failed:  { cls: 'text-red-400 bg-red-500/10 border-red-500/30',             label: 'Failed',  icon: <XCircle size={9} /> },
  };
  const m = map[status] ?? map.queued;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-bold border ${m.cls}`}>
      {m.icon} {m.label}
    </span>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────
export default function UserNetworkVapt() {
  const cached = readCache();

  const [scans,        setScans]        = useState((cached?.scans ?? []).map(normalizeScan));
  const [vulns,        setVulns]        = useState(cached?.vulns ?? []);
  const [refreshing,   setRefreshing]   = useState(false);
  const [error,        setError]        = useState(false);
  const [scanState,    setScanState]    = useState('idle');
  const [expandedVulns, setExpandedVulns] = useState(new Set());

  const [openTerms, setOpenTerms] = useState(() => {
    const persisted = readOpenTerms();
    const autoOpen  = {};
    (cached?.scans ?? []).forEach((s) => {
      if (s.status === 'running' || s.status === 'queued') autoOpen[s.id] = true;
    });
    return { ...persisted, ...autoOpen };
  });

  const [filterSev,    setFilterSev]    = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');
  const [targetRange,  setTargetRange]  = useState('');
  const [scanSearch,   setScanSearch]   = useState('');
  const [findingSearch, setFindingSearch] = useState('');
  const [exporting,    setExporting]    = useState(null);
  const [emailing,     setEmailing]     = useState(null);
  const [approvals,    setApprovals]    = useState({});
  const [ownerForm,    setOwnerForm]    = useState({});  // scanId -> {name,email}

  const activeScansRef = useRef([]);
  const prevScansRef   = useRef((cached?.scans ?? []).map(normalizeScan));
  const isSyncingRef   = useRef(false);
  const notifiedRef    = useRef(new Set()); // prevents duplicate toasts

  useEffect(() => {
    activeScansRef.current = scans.filter(s => s.status === 'running' || s.status === 'queued');
  }, [scans]);

  useEffect(() => { writeOpenTerms(openTerms); }, [openTerms]);

  const activeScans  = scans.filter(s => s.status === 'running' || s.status === 'queued');
  const historyScans = scans.filter(s => s.status !== 'running' && s.status !== 'queued');

  // ── Full sync ───────────────────────────────────────────────────────────────
  const fetchData = useCallback(async (silent = false) => {
    if (isSyncingRef.current) return;
    isSyncingRef.current = true;
    if (!silent) setRefreshing(true);
    try {
      const [sr, vr] = await Promise.all([
        axios.get('/user/vapt/network/scans'),
        axios.get('/user/vapt/network/vulnerabilities'),
      ]);
      const fresh      = (sr.data?.data ?? []).map(normalizeScan);
      const freshVulns = vr.data?.data ?? [];

      fresh.forEach((f) => {
        const prev = prevScansRef.current.find(s => s.id === f.id);
        if (!prev) return;
        const key = `${f.id}-${f.status}`;
        if (notifiedRef.current.has(key)) return; // already toasted
        if (prev.status !== 'done' && f.status === 'done') {
          notifiedRef.current.add(key);
          const total = (f.vulns?.critical ?? 0) + (f.vulns?.high ?? 0) + (f.vulns?.medium ?? 0) + (f.vulns?.low ?? 0);
          if (total === 0) toast.success(`✅ Scan of ${f.target} complete — no vulnerabilities detected.`, { duration: 5000 });
          else             toast.success(`✅ Scan of ${f.target} complete — ${total} finding${total !== 1 ? 's' : ''} found.`, { duration: 5000 });
          setOpenTerms(p => ({ ...p, [f.id]: true }));
        }
        if (prev.status !== 'failed' && f.status === 'failed') {
          notifiedRef.current.add(key);
          toast.error(`❌ Scan of ${f.target} failed`, { duration: 6000 });
          setOpenTerms(p => ({ ...p, [f.id]: true }));
        }
      });

      prevScansRef.current = fresh;
      setScans(fresh);
      setVulns(freshVulns);
      writeCache(fresh, freshVulns);
      setError(false);

      // Load approval statuses for all done scans silently
      fresh.filter(s => s.status === 'done').forEach(async s => {
        try {
          const res  = await axios.get(`/user/vapt/network/export/${s.id}/approval-status`);
          const data = res.data?.data;
          if (data) setApprovals(p => ({ ...p, [s.id]: data }));
        } catch {}
      });
    } catch {
      setError(true);
    } finally {
      if (!silent) setRefreshing(false);
      isSyncingRef.current = false;
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);
  useEffect(() => {
    const id = setInterval(() => fetchData(true), SYNC_MS);
    return () => clearInterval(id);
  }, [fetchData]);

  // ── Fast poll ───────────────────────────────────────────────────────────────
  useEffect(() => {
    const poll = async () => {
      const active = activeScansRef.current;
      if (!active.length) return;
      const results = await Promise.allSettled(
        active.map(s =>
          axios.get(`/user/vapt/network/scans/${s.id}/status`)
            .then(r => ({ id: s.id, data: normalizeScan(r.data?.data) }))
            .catch(() => null)
        )
      );
      const completed = [];
      setScans(prev => prev.map(scan => {
        const result = results.find(r => r.status === 'fulfilled' && r.value?.id === scan.id);
        if (!result?.value?.data) return scan;
        const upd = result.value.data;
        const wasActive = scan.status === 'running' || scan.status === 'queued';
        const isFinished = upd.status === 'done' || upd.status === 'failed';
        if (wasActive && isFinished) completed.push({ target: scan.target, id: scan.id, newStatus: upd.status });
        return { ...scan, ...upd };
      }));
      completed.forEach(s => {
        const key = `${s.id}-${s.newStatus}`;
        if (notifiedRef.current.has(key)) return;
        notifiedRef.current.add(key);
        if (s.newStatus === 'done') { toast.success(`✅ Scan of ${s.target} complete!`, { duration: 5000 }); setOpenTerms(p => ({ ...p, [s.id]: true })); }
        else { toast.error(`❌ Scan of ${s.target} failed`, { duration: 6000 }); setOpenTerms(p => ({ ...p, [s.id]: true })); }
      });
      if (completed.length) fetchData(true);
    };
    const id = setInterval(poll, POLL_MS);
    return () => clearInterval(id);
  }, [fetchData]);

  // ── Start scan ──────────────────────────────────────────────────────────────
  const startScan = async () => {
    if (!targetRange.trim()) return;
    setScanState('scanning');
    try {
      const res = await axios.post('/user/vapt/network/scan', {
        target:    targetRange,
        scan_type: SCAN_TYPE,
      });
      const newScan = normalizeScan({
        ...(res.data?.data ?? {}),
        status: 'queued', target: targetRange, scan_type: SCAN_TYPE,
        date: new Date().toISOString().slice(0, 10),
        created_at: new Date().toISOString(),
        phase: 'Queued', progress: 0, phase_log: [], vulns: null,
      });
      const newId = newScan.id ?? `tmp_${Date.now()}`;
      const scanWithId = { ...newScan, id: newId };
      setScans(prev => [scanWithId, ...prev]);
      setOpenTerms(prev => ({ ...prev, [newId]: true }));
      prevScansRef.current = [scanWithId, ...prevScansRef.current];
      toast.success('Scan queued successfully!');
      setTargetRange('');
      setTimeout(() => setScanState('idle'), 1500);

      const pollNewScan = async (id, attempts = 0) => {
        if (attempts > 120) return;
        try {
          const r   = await axios.get(`/user/vapt/network/scans/${id}/status`);
          const upd = normalizeScan(r.data?.data);
          setScans(prev => prev.map(s => (s.id === id ? { ...s, ...upd } : s)));
          if (upd.status === 'done' || upd.status === 'failed') {
            const key = `${id}-${upd.status}`;
            if (!notifiedRef.current.has(key)) {
              notifiedRef.current.add(key);
              if (upd.status === 'done') toast.success(`✅ Scan of ${upd.target} complete!`, { duration: 5000 });
              if (upd.status === 'failed') toast.error(`❌ Scan of ${upd.target} failed`, { duration: 6000 });
            }
            setOpenTerms(p => ({ ...p, [id]: true }));
            fetchData(true);
            return;
          }
        } catch {}
        setTimeout(() => pollNewScan(id, attempts + 1), 1000);
      };
      if (newId && !String(newId).startsWith('tmp_')) setTimeout(() => pollNewScan(newId), 300);
    } catch (err) {
      setScanState('idle');
      const errors  = err.response?.data?.errors;
      const message = err.response?.data?.message || (errors ? Object.values(errors).flat().join(' ') : 'Failed to start scan');
      toast.error(message);
    }
  };

  // ── Export PDF ──────────────────────────────────────────────────────────────
  const exportPdf = async (scan) => {
    setExporting(scan.id);
    try {
      const res  = await axios.get(`/user/vapt/network/export/${scan.id}/pdf`, { responseType: 'blob' });
      const blob = new Blob([res.data], { type: 'application/pdf' });
      const a    = Object.assign(document.createElement('a'), {
        href:     URL.createObjectURL(blob),
        download: `VAPT-Report-${scan.target}-${scan.date}.pdf`,
      });
      a.click();
      URL.revokeObjectURL(a.href);
      toast.success('PDF report downloaded!');
    } catch {
      toast.error('Export failed');
    } finally {
      setExporting(null);
    }
  };

  // ── Request email approval (sends to owner, needs admin approval) ──────────
  const requestEmailApproval = async (scan, ownerName, ownerEmail) => {
    if (!ownerEmail) {
      toast.error('Please enter an owner email first.');
      return;
    }
    setEmailing(scan.id);
    try {
      const res = await axios.post(`/user/vapt/network/export/${scan.id}/request-email`, {
        owner_name:  ownerName  || null,
        owner_email: ownerEmail,
      });
      toast.success(res.data?.message ?? 'Approval request submitted!', { duration: 6000 });
      setApprovals(p => ({ ...p, [scan.id]: { status: 'pending' } }));
      setOwnerForm(p => ({ ...p, [scan.id]: { open: false } }));
    } catch (err) {
      toast.error(err.response?.data?.message ?? 'Failed to submit request');
    } finally {
      setEmailing(null);
    }
  };

  // ── Poll approval statuses for pending requests ─────────────────────────────
  useEffect(() => {
    const checkApprovals = async () => {
      const pendingIds = Object.entries(approvals)
        .filter(([, v]) => v?.status === 'pending')
        .map(([k]) => k);
      if (!pendingIds.length) return;
      for (const scanId of pendingIds) {
        try {
          const res  = await axios.get(`/user/vapt/network/export/${scanId}/approval-status`);
          const data = res.data?.data;
          if (!data) continue;
          const prev = approvals[scanId]?.status;
          if (data.status !== prev) {
            setApprovals(p => ({ ...p, [scanId]: data }));
            if (data.status === 'approved') {
              toast.success('✅ Your report request was approved — the email has been sent to the network owner!', { duration: 7000 });
            } else if (data.status === 'rejected') {
              const note = data.admin_note ? ` Reason: ${data.admin_note}` : '';
              toast.error(`❌ Your report request was rejected by the admin.${note}`, { duration: 7000 });
            }
          }
        } catch {}
      }
    };
    const id = setInterval(checkApprovals, 5000);
    return () => clearInterval(id);
  }, [approvals]);

  // ── Counts ──────────────────────────────────────────────────────────────────
  const counts = {
    critical: vulns.filter(v => v.severity === 'critical').length,
    high:     vulns.filter(v => v.severity === 'high').length,
    medium:   vulns.filter(v => v.severity === 'medium').length,
    low:      vulns.filter(v => v.severity === 'low').length,
  };

  const filteredVulns = vulns.filter(v =>
    (filterSev    === 'all' || v.severity === filterSev) &&
    (filterStatus === 'all' || v.status   === filterStatus) &&
    (!findingSearch.trim() ||
      v.title?.toLowerCase().includes(findingSearch.toLowerCase()) ||
      v.host?.toLowerCase().includes(findingSearch.toLowerCase()) ||
      v.cve_id?.toLowerCase().includes(findingSearch.toLowerCase()) ||
      v.service?.toLowerCase().includes(findingSearch.toLowerCase()))
  );

  const totalRisk = counts.critical * 4 + counts.high * 3 + counts.medium * 2 + counts.low;
  const riskLevel = totalRisk === 0 ? 'Secure' : totalRisk < 5 ? 'Low Risk' : totalRisk < 15 ? 'Moderate' : totalRisk < 30 ? 'High Risk' : 'Critical';
  const riskColor = totalRisk === 0 ? 'text-emerald-400' : totalRisk < 5 ? 'text-sky-400' : totalRisk < 15 ? 'text-amber-400' : totalRisk < 30 ? 'text-orange-400' : 'text-red-400';


  // ── Render ──────────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-[#0f1623] px-4 py-6 space-y-5 w-full">
      {refreshing && (
        <div className="fixed top-0 left-0 right-0 z-50 h-0.5 overflow-hidden" style={{background:'#1e2a3a'}}>
          <div className="h-full bg-cyan-500" style={{ width: '60%', animation: 'indeterminate 1.2s ease-in-out infinite' }} />
        </div>
      )}
      <style>{`
        @keyframes indeterminate { 0%{transform:translateX(-100%) scaleX(.4)} 50%{transform:translateX(0) scaleX(.8)} 100%{transform:translateX(100%) scaleX(.4)} }
        @keyframes pulse2 { 0%,100%{opacity:1} 50%{opacity:.4} }
      `}</style>

      {/* ── Header ── */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" style={{animation:'pulse2 2s infinite'}} />
            <span className="text-emerald-400 text-sm font-semibold tracking-widest uppercase">Network VAPT</span>
          </div>
          <h1 className="text-white text-4xl font-bold tracking-tight leading-none">Vulnerability Scanner</h1>
          <p className="text-gray-400 text-base mt-2">Scan your network for vulnerabilities and CVE exposures</p>
        </div>
        <div className="flex items-center gap-3 flex-shrink-0 pt-1">
          {activeScans.length > 0 && (
            <div className="flex items-center gap-2 text-cyan-400 text-sm bg-cyan-500/10 border border-cyan-500/20 px-4 py-2 rounded-xl">
              <Radio size={13} className="animate-pulse" />
              {activeScans.length} live
            </div>
          )}
          {error && (
            <div className="flex items-center gap-2 text-red-400 text-sm bg-red-500/10 border border-red-500/20 px-4 py-2 rounded-xl">
              <XCircle size={13} /> Server error —{' '}
              <button onClick={() => { setError(false); fetchData(); }} className="underline">retry</button>
            </div>
          )}
          {refreshing && !activeScans.length && (
            <span className="text-gray-600 text-sm flex items-center gap-1.5"><Loader2 size={13} className="animate-spin" />syncing</span>
          )}
        </div>
      </div>

      {/* ── Top stat cards ── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-5">
        {[
          { icon: ShieldAlert,   label: 'Critical', value: counts.critical, sev: 'critical', range: '9.0–10.0', sub: 'Patch immediately'  },
          { icon: AlertTriangle, label: 'High',     value: counts.high,     sev: 'high',     range: '7.0–8.9',  sub: 'Remediate soon'    },
          { icon: Shield,        label: 'Medium',   value: counts.medium,   sev: 'medium',   range: '4.0–6.9',  sub: 'Plan remediation'  },
          { icon: ShieldCheck,   label: 'Low',      value: counts.low,      sev: 'low',      range: '0.1–3.9',  sub: 'Low urgency'       },
        ].map(({ icon: Icon, label, value, sev, range, sub }) => {
          const m = SEVERITY[sev];
          return (
            <div key={label} className="rounded-2xl p-6 flex flex-col gap-4" style={{background:'#151f2e', border:'1px solid #1e2d42'}}>
              <div className="flex items-center justify-between">
                <div className={`w-11 h-11 rounded-2xl flex items-center justify-center ${m.bg} border ${m.border}`}>
                  <Icon size={20} className={m.color} />
                </div>
                <span className={`w-3 h-3 rounded-full ${value > 0 ? m.dot : 'bg-gray-700'}`} />
              </div>
              <div>
                <p className="text-white text-5xl font-bold leading-none">{value}</p>
                <p className={`text-base font-semibold mt-2 ${m.color}`}>{label}</p>
                <p className="text-gray-500 text-sm mt-0.5">{sub}</p>
              </div>
              <div className="flex items-center justify-between mt-auto pt-2 border-t" style={{borderColor:'#1e2d42'}}>
                <span className="text-gray-500 text-sm font-mono">CVSS {range}</span>
                {totalRisk > 0 && value > 0 && (
                  <span className={`text-sm font-bold ${riskColor}`}>{riskLevel}</span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* ── Scanner ── */}
      <div className="rounded-2xl overflow-hidden" style={{background:'#151f2e', border:'1px solid #1e2d42'}}>
          <div className="px-6 py-5 flex items-center gap-3" style={{borderBottom:'1px solid #1e2d42', background:'linear-gradient(90deg,rgba(6,182,212,0.05),transparent)'}}>
            <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0" style={{background:'rgba(6,182,212,0.12)', border:'1px solid rgba(6,182,212,0.25)'}}>
              <Target size={18} className="text-cyan-400" />
            </div>
            <div>
              <p className="text-white font-semibold text-base">Vulnerability Scanner</p>
              <p className="text-gray-400 text-sm mt-0.5">Full port scan · CVE detection · All severity levels</p>
            </div>
          </div>
          <div className="p-6 space-y-4">
            <div>
              <label className="block text-gray-400 text-sm mb-2 uppercase tracking-widest font-semibold">Target IP or Range</label>
              <div className="flex gap-3">
                <input
                  type="text" value={targetRange}
                  onChange={e => setTargetRange(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && startScan()}
                  disabled={scanState === 'scanning'}
                  placeholder="192.168.1.1  or  10.0.0.0/24"
                  className="flex-1 text-white text-base font-mono px-5 py-3.5 rounded-xl focus:outline-none focus:ring-1 focus:ring-cyan-500/40 disabled:opacity-50 placeholder:text-gray-600 transition"
                  style={{background:'#0f1623', border:'1px solid #1e2d42'}}
                />
                <button onClick={startScan} disabled={!targetRange.trim() || scanState === 'scanning'}
                  className="flex items-center gap-2 px-7 py-3.5 rounded-xl text-base font-semibold transition-all whitespace-nowrap disabled:opacity-30"
                  style={{background: scanState==='scanning' ? 'rgba(217,119,6,0.7)' : '#0891b2', color:'white'}}>
                  {scanState === 'scanning' ? <><Loader2 size={16} className="animate-spin" />Queuing...</> : <><Play size={16} />Run Scan</>}
                </button>
              </div>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {[
                { icon: Cpu,        label: 'Full CVE Detection',  sub: 'Detects known vulnerabilities' },
                { icon: Wifi,       label: 'All 65,535 Ports',    sub: 'Complete port coverage'        },
                { icon: TrendingUp, label: 'All Severity Levels', sub: 'Critical to Low'               },
                { icon: Lock,       label: 'Read-only',           sub: 'No exploitation ever'          },
              ].map(({ icon: Icon, label, sub }) => (
                <div key={label} className="flex items-center gap-3 px-4 py-3 rounded-xl" style={{background:'#0f1623', border:'1px solid #1e2d42'}}>
                  <Icon size={16} className="text-cyan-600 flex-shrink-0" />
                  <div>
                    <p className="text-gray-300 text-sm font-medium leading-none">{label}</p>
                    <p className="text-gray-500 text-xs mt-0.5">{sub}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

      {/* ── Active Scans ── */}
      {activeScans.length > 0 && (
        <div className="rounded-2xl overflow-hidden" style={{background:'#151f2e', border:'1px solid #1e2d42'}}>
          <div className="px-5 py-3.5 flex items-center gap-2" style={{borderBottom:'1px solid #1e2d42'}}>
            <Activity size={14} className="text-cyan-400" />
            <span className="text-white font-semibold text-sm">Active Scans</span>
            <span className="text-gray-600 text-xs">{activeScans.length} running</span>
            <button onClick={() => { const a = activeScans.some(s => openTerms[s.id]); const n = {}; activeScans.forEach(s => { n[s.id] = !a; }); setOpenTerms(p => ({...p,...n})); }}
              className="ml-auto text-xs text-gray-500 hover:text-gray-300 flex items-center gap-1">
              <Terminal size={11} />{activeScans.some(s => openTerms[s.id]) ? 'Hide logs' : 'Show logs'}
            </button>
          </div>
          <div className={`p-4 grid gap-3 ${activeScans.length === 1 ? 'grid-cols-1' : 'grid-cols-1 md:grid-cols-2'}`}>
            {activeScans.map(scan => (
              <ActiveScanCard key={scan.id} scan={scan} showTerm={!!openTerms[scan.id]}
                onToggleTerm={() => setOpenTerms(p => ({...p,[scan.id]:!p[scan.id]}))} />
            ))}
          </div>
        </div>
      )}

      {/* ── Scan History + Findings row ── */}
      <div className="grid md:grid-cols-5 gap-4 items-start">

        {/* Scan History — 2 cols */}
        {historyScans.length > 0 && (
          <div className="md:col-span-2 rounded-2xl overflow-hidden" style={{background:'#151f2e', border:'1px solid #1e2d42'}}>
            <div className="px-6 py-4 flex items-center gap-2" style={{borderBottom:'1px solid #1e2d42'}}>
              <Clock size={16} className="text-gray-400" />
              <span className="text-white font-semibold text-base">Scan History</span>
              <span className="text-gray-500 text-sm ml-auto">{historyScans.length} scans</span>
            </div>
            {/* Search bar */}
            <div className="px-4 py-2.5" style={{borderBottom:'1px solid #1e2d42'}}>
              <input
                type="text"
                value={scanSearch}
                onChange={e => setScanSearch(e.target.value)}
                placeholder="Search by IP or network..."
                className="w-full text-white text-sm px-3 py-2 rounded-lg placeholder:text-gray-600 focus:outline-none focus:ring-1 focus:ring-cyan-500/30 transition"
                style={{background:'#0f1623', border:'1px solid #1e2d42'}}
              />
            </div>
            <div className="overflow-y-auto" style={{maxHeight: '480px'}}>
              <div className="divide-y" style={{borderColor:'#1e2d42'}}>
              {refreshing && historyScans.length === 0 && [1,2,3].map(n => <SkeletonRow key={n} />)}
              {historyScans
                .filter(s => !scanSearch.trim() || s.target.toLowerCase().includes(scanSearch.toLowerCase()))
                .map((scan, idx) => {
                const showTerm = !!openTerms[scan.id];
                const isLatestForTarget = historyScans.findIndex(s => s.target === scan.target) === idx;
                const approvalStatus    = approvals[scan.id]?.status;
                const hasNewerScan      = historyScans.some((s, i) => s.target === scan.target && i < idx);
                const canEmailOwner     = isLatestForTarget && !hasNewerScan;
                return (
                  <div key={scan.id} className="px-6 py-4 hover:bg-white/[0.02] transition-colors" style={{borderColor:'#1e2d42'}}>
                    <div className="flex items-center gap-3">
                      <StatusBadge status={scan.status} />
                      <div className="flex-1 min-w-0">
                        <p className="text-white font-mono font-bold text-base truncate">{scan.target}</p>
                        <p className="text-gray-400 text-sm mt-1 flex items-center gap-1.5"><Clock size={12}/>{scan.date}</p>
                      </div>
                    </div>
                    {scan.vulns && (
                      <div className="flex gap-2 mt-3 flex-wrap items-center">
                        {(scan.vulns.critical + scan.vulns.high + scan.vulns.medium + scan.vulns.low) === 0 ? (
                          <span className="text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-3 py-1.5 rounded-lg text-sm font-semibold flex items-center gap-1.5">
                            <Shield size={13} /> No vulnerabilities detected
                          </span>
                        ) : (
                          <>
                            {scan.vulns.critical > 0 && <span className="text-red-400 bg-red-500/10 border border-red-500/20 px-3 py-1 rounded-lg text-sm font-bold">{scan.vulns.critical} Critical</span>}
                            {scan.vulns.high > 0     && <span className="text-orange-400 bg-orange-500/10 border border-orange-500/20 px-3 py-1 rounded-lg text-sm font-bold">{scan.vulns.high} High</span>}
                            {scan.vulns.medium > 0   && <span className="text-amber-400 bg-amber-500/10 border border-amber-500/20 px-3 py-1 rounded-lg text-sm font-bold">{scan.vulns.medium} Medium</span>}
                            {scan.vulns.low > 0      && <span className="text-sky-400 bg-sky-500/10 border border-sky-500/20 px-3 py-1 rounded-lg text-sm font-bold">{scan.vulns.low} Low</span>}
                          </>
                        )}
                        <div className="ml-auto flex gap-2">
                          <button onClick={() => setOpenTerms(p => ({...p,[scan.id]:!p[scan.id]}))}
                            className="text-sm px-3 py-1.5 rounded-lg border transition"
                            style={{color: showTerm ? '#22d3ee' : '#9ca3af', background: showTerm ? 'rgba(6,182,212,0.08)' : 'rgba(255,255,255,0.03)', borderColor: showTerm ? 'rgba(6,182,212,0.2)' : '#1e2d42'}}>
                            {showTerm ? 'Hide' : 'Logs'}
                          </button>
                          {scan.status === 'done' && (
                            <>
                              <button onClick={() => exportPdf(scan)} disabled={exporting === scan.id}
                                className="text-sm px-3 py-1.5 rounded-lg border transition flex items-center gap-1.5"
                                style={{color:'#22d3ee', background:'rgba(6,182,212,0.08)', borderColor:'rgba(6,182,212,0.2)'}}>
                                {exporting === scan.id ? <Loader2 size={12} className="animate-spin" /> : <Download size={12} />}
                                Report
                              </button>
                              {canEmailOwner && approvalStatus !== 'rejected' && (
                                <button
                                  onClick={() => {
                                    if (approvalStatus === 'approved' || approvalStatus === 'pending') return;
                                    const current = ownerForm[scan.id];
                                    if (current?.open) {
                                      setOwnerForm(p => ({ ...p, [scan.id]: { ...p[scan.id], open: false } }));
                                    } else {
                                      setOwnerForm(p => ({ ...p, [scan.id]: { open: true, name: scan.owner_name || '', email: scan.owner_email || '' } }));
                                    }
                                  }}
                                  disabled={approvalStatus === 'approved' || approvalStatus === 'pending'}
                                  className="text-sm px-3 py-1.5 rounded-lg border transition disabled:opacity-60 disabled:cursor-not-allowed"
                                  style={{
                                    color: approvalStatus==='approved'?'#4ade80': approvalStatus==='pending'?'#fbbf24':'#a78bfa',
                                    background: approvalStatus==='approved'?'rgba(74,222,128,0.08)': approvalStatus==='pending'?'rgba(251,191,36,0.08)':'rgba(167,139,250,0.08)',
                                    borderColor: approvalStatus==='approved'?'rgba(74,222,128,0.25)': approvalStatus==='pending'?'rgba(251,191,36,0.25)':'rgba(167,139,250,0.2)',
                                  }}>
                                  {approvalStatus==='pending' ? '⏳ Pending' : approvalStatus==='approved' ? '✅ Sent' : '✉ Email Owner'}
                                </button>
                              )}
                              {canEmailOwner && approvalStatus === 'rejected' && (
                                <span className="text-red-400/70 text-sm flex items-center gap-1">
                                  ❌ Rejected — rescan to retry
                                </span>
                              )}
                            </>
                          )}
                        </div>
                      </div>
                    )}
                    {scan.status === 'failed' && (
                      <p className="text-red-400/70 text-sm mt-2 flex items-center gap-1.5"><XCircle size={12}/>{scan.error_message ?? 'Scan failed'}</p>
                    )}

                    {/* Owner email form */}
                    {ownerForm[scan.id]?.open && (
                      <div className="mt-4 p-4 rounded-xl space-y-3" style={{background:'#0f1623', border:'1px solid rgba(167,139,250,0.2)'}}>
                        <p className="text-purple-300 text-sm font-semibold">Send PDF report to network owner</p>
                        <div className="grid grid-cols-2 gap-3">
                          <div>
                            <label className="text-gray-500 text-xs uppercase tracking-wide font-semibold block mb-1.5">Owner Name</label>
                            <input type="text"
                              value={ownerForm[scan.id]?.name ?? ''}
                              onChange={e => setOwnerForm(p => ({ ...p, [scan.id]: { ...p[scan.id], name: e.target.value } }))}
                              placeholder="e.g. John Smith"
                              className="w-full text-white text-xs px-3 py-2 rounded-lg placeholder:text-gray-700 focus:outline-none"
                              style={{background:'#151f2e', border:'1px solid #1e2d42'}}
                            />
                          </div>
                          <div>
                            <label className="text-gray-500 text-[10px] uppercase tracking-wide font-semibold block mb-1">Owner Email *</label>
                            <input type="email"
                              value={ownerForm[scan.id]?.email ?? ''}
                              onChange={e => setOwnerForm(p => ({ ...p, [scan.id]: { ...p[scan.id], email: e.target.value } }))}
                              placeholder="owner@company.com"
                              className="w-full text-white text-xs px-3 py-2 rounded-lg placeholder:text-gray-700 focus:outline-none"
                              style={{background:'#151f2e', border:'1px solid #1e2d42'}}
                            />
                          </div>
                        </div>
                        <div className="flex gap-2 justify-end">
                          <button onClick={() => setOwnerForm(p => ({ ...p, [scan.id]: { open: false } }))}
                            className="text-xs px-3 py-1.5 rounded-lg border text-gray-500 hover:text-gray-300 transition"
                            style={{borderColor:'#1e2d42'}}>
                            Cancel
                          </button>
                          <button
                            disabled={!ownerForm[scan.id]?.email || emailing === scan.id}
                            onClick={() => requestEmailApproval(scan, ownerForm[scan.id]?.name, ownerForm[scan.id]?.email)}
                            className="text-xs px-3 py-1.5 rounded-lg font-semibold transition disabled:opacity-40"
                            style={{color:'#a78bfa', background:'rgba(167,139,250,0.12)', border:'1px solid rgba(167,139,250,0.3)'}}>
                            {emailing === scan.id ? '...' : '✉ Request Approval'}
                          </button>
                        </div>
                      </div>
                    )}
                    {showTerm && (
                      <div className="mt-3 space-y-2">
                        <StagePipeline scan={scan} />
                        <ScanTerminal scan={scan} />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
            </div>
          </div>
        )}

        {/* Findings — 3 cols */}
        <div className={`rounded-2xl overflow-hidden ${historyScans.length > 0 ? 'md:col-span-3' : 'md:col-span-5'}`} style={{background:'#151f2e', border:'1px solid #1e2d42'}}>
          <div className="px-6 py-4 flex flex-wrap items-center gap-2" style={{borderBottom:'1px solid #1e2d42'}}>
            <Shield size={16} className="text-gray-400" />
            <span className="text-white font-semibold text-base">Findings</span>
            <div className="flex gap-1.5 ml-1">
              {['all','critical','high','medium','low'].map(s => {
                const m = SEVERITY[s];
                return (
                  <button key={s} onClick={() => setFilterSev(s)}
                    className="px-3 py-1 rounded-lg text-sm font-semibold capitalize transition"
                    style={{
                      color: filterSev === s ? (s === 'all' ? '#fff' : m?.color?.replace('text-','')) : '#6b7280',
                      background: filterSev === s ? (s === 'all' ? '#374151' : 'rgba(255,255,255,0.05)') : 'transparent',
                      border: `1px solid ${filterSev === s ? (s === 'all' ? '#4b5563' : '#2d3748') : 'transparent'}`,
                    }}>
                    {s}
                  </button>
                );
              })}
            </div>
            <div className="h-4 w-px" style={{background:'#1e2d42'}} />
            <div className="flex gap-1.5">
              {['all','open','resolved'].map(s => (
                <button key={s} onClick={() => setFilterStatus(s)}
                  className="px-3 py-1 rounded-lg text-sm font-semibold capitalize transition"
                  style={{color: filterStatus===s ? '#fff' : '#6b7280', background: filterStatus===s ? '#374151' : 'transparent', border:`1px solid ${filterStatus===s ? '#4b5563' : 'transparent'}`}}>
                  {s}
                </button>
              ))}
            </div>
            <span className="text-gray-500 text-sm ml-auto">{filteredVulns.length} finding{filteredVulns.length!==1?'s':''}</span>
          </div>
          {/* Findings search */}
          <div className="px-4 py-2.5" style={{borderBottom:'1px solid #1e2d42'}}>
            <input
              type="text"
              value={findingSearch}
              onChange={e => setFindingSearch(e.target.value)}
              placeholder="Search by title, host, CVE ID or service..."
              className="w-full text-white text-sm px-3 py-2 rounded-lg placeholder:text-gray-600 focus:outline-none focus:ring-1 focus:ring-cyan-500/30 transition"
              style={{background:'#0f1623', border:'1px solid #1e2d42'}}
            />
          </div>

          {filteredVulns.length === 0 ? (
            <div className="text-center py-20">
              <Shield size={36} className="mx-auto mb-4 text-gray-800" />
              <p className="text-lg text-gray-500">{vulns.length === 0 ? 'No vulnerabilities found yet.' : 'No findings match filters.'}</p>
              {vulns.length === 0 && <p className="text-sm text-gray-600 mt-1.5">Run a scan above to begin.</p>}
            </div>
          ) : (
            <div className="overflow-y-auto" style={{maxHeight: '640px'}}>
            <div className="divide-y" style={{borderColor:'#1e2d42'}}>
              {filteredVulns.map(v => {
                const m = SEVERITY[v.severity] ?? SEVERITY.low;
                const isOpen = expandedVulns.has(v.id);
                const toggle = () => setExpandedVulns(prev => {
                  const next = new Set(prev);
                  next.has(v.id) ? next.delete(v.id) : next.add(v.id);
                  return next;
                });
                return (
                  <div key={v.id} className="transition-colors" style={{background: isOpen ? 'rgba(255,255,255,0.02)' : 'transparent'}}>
                    <button onClick={toggle}
                      className="w-full flex items-center gap-4 px-6 py-5 text-left hover:bg-white/[0.02] transition-colors">
                      <div className={`w-16 h-16 rounded-2xl flex items-center justify-center flex-shrink-0 ${m.bg} border ${m.border}`}>
                        <span className={`text-xl font-bold font-mono ${m.color}`}>{v.cvss}</span>
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-2 flex-wrap">
                          <SeverityBadge severity={v.severity} />
                          {v.cve_id && <span className="text-indigo-400 text-sm font-mono bg-indigo-500/10 border border-indigo-500/20 px-2.5 py-0.5 rounded-lg">{v.cve_id}</span>}
                          <span className={`text-sm px-2.5 py-0.5 rounded-lg font-semibold border ${v.status==='open'?'text-red-400 bg-red-500/10 border-red-500/20':'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'}`}>
                            {v.status === 'open' ? 'Open' : 'Resolved'}
                          </span>
                        </div>
                        <p className="text-white font-semibold text-base truncate">{v.title}</p>
                        <p className="text-gray-400 text-sm mt-1 font-mono">{v.host}:{v.port} · {v.service}</p>
                      </div>
                      {isOpen ? <ChevronUp size={16} className="text-gray-500 flex-shrink-0"/> : <ChevronDown size={16} className="text-gray-500 flex-shrink-0"/>}
                    </button>

                    {isOpen && (
                      <div className="px-6 pb-6 pt-2 space-y-4" style={{borderTop:'1px solid #1e2d42'}}>
                        <div className="grid grid-cols-3 gap-4">
                          {[
                            {label:'Host',           value: v.host},
                            {label:'Port / Service', value: `${v.port} / ${v.service}`},
                            {label:'CVSS Score',     value: `${v.cvss} / 10.0`, color: m.color},
                          ].map(f => (
                            <div key={f.label} className="px-5 py-4 rounded-2xl" style={{background:'#0f1623', border:'1px solid #1e2d42'}}>
                              <p className="text-gray-500 text-xs uppercase tracking-widest font-semibold mb-2">{f.label}</p>
                              <p className={`text-base font-bold font-mono ${f.color ?? 'text-white'}`}>{f.value}</p>
                            </div>
                          ))}
                        </div>
                        <CveIdBlock vuln={v} />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}