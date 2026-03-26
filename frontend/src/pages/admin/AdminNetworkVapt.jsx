import { useState, useEffect, useRef } from 'react';
import {
  Download, ShieldAlert, Shield, ShieldCheck,
  ChevronDown, ChevronUp, Users, Trash2,
  CheckCircle2, Clock, Activity, Loader2, XCircle,
  RefreshCw, Radio,
} from 'lucide-react';
import axios from '../../api/axios';
import toast from 'react-hot-toast';

const POLL_MS         = 3000;
const ADMIN_CACHE_KEY = 'vapt_admin_cache_v2';

function readCache()      { try { return JSON.parse(localStorage.getItem(ADMIN_CACHE_KEY)) ?? null; } catch { return null; } }
function writeCache(s, v) { try { localStorage.setItem(ADMIN_CACHE_KEY, JSON.stringify({ scans: s, vulns: v })); } catch {} }

const SEV = {
  critical: { color: '#f87171', bg: 'rgba(248,113,113,0.1)',  border: 'rgba(248,113,113,0.3)',  dot: '#f87171', label: 'Critical' },
  high:     { color: '#fb923c', bg: 'rgba(251,146,60,0.1)',   border: 'rgba(251,146,60,0.3)',   dot: '#fb923c', label: 'High'     },
  medium:   { color: '#fbbf24', bg: 'rgba(251,191,36,0.1)',   border: 'rgba(251,191,36,0.3)',   dot: '#fbbf24', label: 'Medium'   },
  low:      { color: '#38bdf8', bg: 'rgba(56,189,248,0.1)',   border: 'rgba(56,189,248,0.3)',   dot: '#38bdf8', label: 'Low'      },
};

function useElapsed(d) {
  const [e, setE] = useState(0);
  useEffect(() => {
    const s = new Date(d).getTime();
    if (isNaN(s)) return;
    const tick = () => setE(Math.floor((Date.now()-s)/1000));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [d]);
  return e;
}
function fmt(s) { const t=Math.max(0,Number(s)||0),m=Math.floor(t/60); return m>0?`${m}m ${String(t%60).padStart(2,'0')}s`:`${t%60}s`; }

// ─── Card wrapper ─────────────────────────────────────────────────────────────
function Card({ children, style, className = '' }) {
  return (
    <div className={`rounded-2xl overflow-hidden ${className}`}
      style={{background:'#151f2e', border:'1px solid #1e2d42', ...style}}>
      {children}
    </div>
  );
}
function CardHeader({ children }) {
  return (
    <div className="px-6 py-4 flex items-center gap-3 flex-wrap" style={{borderBottom:'1px solid #1e2d42'}}>
      {children}
    </div>
  );
}

// ─── Status badge ─────────────────────────────────────────────────────────────
function StatusBadge({ status }) {
  const map = {
    done:    { bg:'rgba(52,211,153,0.12)', border:'rgba(52,211,153,0.3)', color:'#34d399', label:'Done'    },
    running: { bg:'rgba(34,211,238,0.12)', border:'rgba(34,211,238,0.3)', color:'#22d3ee', label:'Running' },
    queued:  { bg:'rgba(251,191,36,0.12)', border:'rgba(251,191,36,0.3)', color:'#fbbf24', label:'Queued'  },
    failed:  { bg:'rgba(248,113,113,0.1)', border:'rgba(248,113,113,0.3)',color:'#f87171', label:'Failed'  },
  };
  const m = map[status] ?? map.queued;
  return (
    <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-sm font-bold"
      style={{background:m.bg, border:`1px solid ${m.border}`, color:m.color}}>
      {(status==='running'||status==='queued') && <span className="w-2 h-2 rounded-full bg-current animate-pulse"/>}
      {status==='done'   && <CheckCircle2 size={12}/>}
      {status==='failed' && <XCircle size={12}/>}
      {m.label}
    </span>
  );
}

// ─── Severity badge ───────────────────────────────────────────────────────────
function SevBadge({ severity }) {
  const m = SEV[severity] ?? SEV.low;
  return (
    <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-sm font-bold"
      style={{background:m.bg, border:`1px solid ${m.border}`, color:m.color}}>
      <span className="w-2 h-2 rounded-full" style={{background:m.dot}}/>{m.label}
    </span>
  );
}

// ─── Scan Row ─────────────────────────────────────────────────────────────────
function ScanRow({ scan, onDelete, onReport, loadingId }) {
  const elapsed  = useElapsed(scan.created_at ?? scan.date);
  const stuck    = elapsed > 600;
  const isActive = scan.status === 'running' || scan.status === 'queued';
  const total    = scan.vulns ? scan.vulns.critical+scan.vulns.high+scan.vulns.medium+scan.vulns.low : -1;

  return (
    <div style={{padding:'18px 24px', borderBottom:'1px solid #1e2d42'}}
      className="hover:bg-white/[0.01] transition-colors">
      <div className="flex items-center gap-4 flex-wrap">
        <StatusBadge status={scan.status}/>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            <span className="text-white font-mono font-bold text-base">{scan.target}</span>
            <span className="text-gray-400 text-sm flex items-center gap-1.5"><Users size={12}/>{scan.user}</span>
            <span className="text-gray-500 text-sm flex items-center gap-1.5"><Clock size={12}/>{scan.date}</span>
          </div>
          {isActive && (
            <p className={`text-sm mt-1.5 flex items-center gap-2 ${stuck?'text-red-400':'text-cyan-400'}`}>
              <span className={`w-2 h-2 rounded-full ${stuck?'bg-red-400':'bg-cyan-400 animate-pulse'}`}/>
              {fmt(elapsed)}{stuck?' — ⚠ possibly stuck':''}
            </p>
          )}
          {scan.status === 'failed' && <p className="text-red-400/70 text-sm mt-1 flex items-center gap-1.5"><XCircle size={12}/>Scan failed</p>}
        </div>

        {scan.vulns && (
          <div className="flex gap-2 flex-wrap">
            {total === 0 ? (
              <span className="text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-3 py-1 rounded-lg text-sm font-semibold flex items-center gap-1.5">
                <Shield size={13}/> No vulnerabilities
              </span>
            ) : (
              <>
                {scan.vulns.critical > 0 && <span style={{color:'#f87171',background:'rgba(248,113,113,0.1)',border:'1px solid rgba(248,113,113,0.25)'}} className="px-3 py-1 rounded-lg text-sm font-bold">{scan.vulns.critical} Critical</span>}
                {scan.vulns.high     > 0 && <span style={{color:'#fb923c',background:'rgba(251,146,60,0.1)', border:'1px solid rgba(251,146,60,0.25)'}} className="px-3 py-1 rounded-lg text-sm font-bold">{scan.vulns.high} High</span>}
                {scan.vulns.medium   > 0 && <span style={{color:'#fbbf24',background:'rgba(251,191,36,0.1)', border:'1px solid rgba(251,191,36,0.25)'}} className="px-3 py-1 rounded-lg text-sm font-bold">{scan.vulns.medium} Medium</span>}
                {scan.vulns.low      > 0 && <span style={{color:'#38bdf8',background:'rgba(56,189,248,0.1)', border:'1px solid rgba(56,189,248,0.25)'}} className="px-3 py-1 rounded-lg text-sm font-bold">{scan.vulns.low} Low</span>}
              </>
            )}
          </div>
        )}

        <div className="flex items-center gap-2 flex-shrink-0">
          {scan.status === 'done' && (
            <button onClick={() => onReport(scan)} disabled={loadingId === scan.id}
              className="flex items-center gap-2 text-sm px-4 py-2 rounded-xl border transition font-semibold"
              style={{color:'#22d3ee', background:'rgba(6,182,212,0.08)', borderColor:'rgba(6,182,212,0.25)'}}>
              {loadingId === scan.id ? <Loader2 size={13} className="animate-spin"/> : <Download size={13}/>} Report
            </button>
          )}
          <button onClick={() => onDelete(scan.id)}
            className="p-2 rounded-xl transition text-gray-600 hover:text-red-400 hover:bg-red-500/10" title="Delete">
            <Trash2 size={16}/>
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Main ─────────────────────────────────────────────────────────────────────
export default function AdminNetworkVapt() {
  const cached = readCache();

  const [activeTab,     setActiveTab]     = useState('scans');
  const [scans,         setScans]         = useState(cached?.scans ?? []);
  const [vulns,         setVulns]         = useState(cached?.vulns ?? []);
  const [approvals,     setApprovals]     = useState([]);
  const [refreshing,    setRefreshing]    = useState(false);
  const [error,         setError]         = useState(false);
  const [expandedVulns, setExpandedVulns] = useState(new Set());
  const [filterSev,     setFilterSev]     = useState('all');
  const [filterStatus,  setFilterStatus]  = useState('all');
  const [exportingAll,  setExportingAll]  = useState(false);
  const [reportId,      setReportId]      = useState(null);
  const [previewId,     setPreviewId]     = useState(null);
  const [approvingId,   setApprovingId]   = useState(null);
  const [scanSearch,    setScanSearch]    = useState('');
  const [vulnSearch,    setVulnSearch]    = useState('');
  const notifiedRef = useRef(new Set());
  const prevScansRef = useRef([]);

  const fetchData = async (silent = false) => {
    if (!silent) setRefreshing(true);
    try {
      const [sr, vr, ar] = await Promise.all([
        axios.get('/admin/vapt/network/scans'),
        axios.get('/admin/vapt/network/vulnerabilities'),
        axios.get('/admin/vapt/email-approvals'),
      ]);
      const freshScans = sr.data.data ?? [];
      freshScans.forEach(f => {
        const prev = prevScansRef.current.find(s => s.id === f.id);
        if (!prev) return;
        const key = `${f.id}-${f.status}`;
        if (notifiedRef.current.has(key)) return;
        if (prev.status !== 'done' && f.status === 'done') {
          notifiedRef.current.add(key);
          const t = (f.vulns?.critical??0)+(f.vulns?.high??0)+(f.vulns?.medium??0)+(f.vulns?.low??0);
          toast.success(`✅ ${f.user}'s scan of ${f.target} complete — ${t>0?t+' finding'+(t!==1?'s found':'found'):'no vulnerabilities'}`, { duration: 5000 });
        }
        if (prev.status !== 'failed' && f.status === 'failed') {
          notifiedRef.current.add(key);
          toast.error(`❌ ${f.user}'s scan of ${f.target} failed`, { duration: 6000 });
        }
      });
      prevScansRef.current = freshScans;
      setScans(freshScans);

      // ── Auto-resolve: if a target's latest done scan is clean, mark its open vulns resolved ──
      let freshVulns = vr.data.data ?? [];
      const doneScansByTarget = freshScans
        .filter(s => s.status === 'done')
        .reduce((acc, s) => {
          // Keep only the most recent done scan per target
          if (!acc[s.target] || new Date(s.created_at ?? s.date) > new Date(acc[s.target].created_at ?? acc[s.target].date)) {
            acc[s.target] = s;
          }
          return acc;
        }, {});

      const autoResolvePromises = [];
      freshVulns = freshVulns.map(v => {
        if (v.status !== 'open') return v;
        const latestScan = doneScansByTarget[v.host] ?? doneScansByTarget[v.target];
        if (!latestScan) return v;
        const total = (latestScan.vulns?.critical ?? 0) + (latestScan.vulns?.high ?? 0) + (latestScan.vulns?.medium ?? 0) + (latestScan.vulns?.low ?? 0);
        if (total === 0) {
          // Fire-and-forget PATCH to backend; update local state optimistically
          autoResolvePromises.push(
            axios.patch(`/admin/vapt/network/vulnerabilities/${v.id}/resolve`).catch(() => {})
          );
          return { ...v, status: 'resolved' };
        }
        return v;
      });

      if (autoResolvePromises.length > 0) {
        await Promise.allSettled(autoResolvePromises);
        const resolvedCount = autoResolvePromises.length;
        toast.success(`🛡️ ${resolvedCount} finding${resolvedCount !== 1 ? 's' : ''} auto-resolved — clean rescan detected`, { duration: 5000 });
      }

      setVulns(freshVulns);
      setApprovals(ar.data.data ?? []);
      writeCache(freshScans, freshVulns);
      setError(false);
    } catch { setError(true); }
    finally { if (!silent) setRefreshing(false); }
  };

  useEffect(() => {
    fetchData();
    const id = setInterval(() => fetchData(true), POLL_MS);
    return () => clearInterval(id);
  }, []);

  const deleteVuln = async (id) => {
    if (!confirm('Delete this vulnerability record?')) return;
    try {
      await axios.delete(`/admin/vapt/network/vulnerabilities/${id}`);
      setVulns(prev => prev.filter(v => v.id !== id));
      toast.success('Vulnerability deleted');
    } catch { toast.error('Failed to delete'); }
  };

  const markResolved = async (id) => {
    try {
      await axios.patch(`/admin/vapt/network/vulnerabilities/${id}/resolve`);
      setVulns(prev => prev.map(v => v.id === id ? { ...v, status: 'resolved' } : v));
      toast.success('Marked as resolved');
    } catch { toast.error('Failed to resolve'); }
  };

  const deleteScan = async (id) => {
    if (!confirm('Delete this scan and all its findings?')) return;
    try {
      await axios.delete(`/admin/vapt/network/scans/${id}`);
      setScans(prev => prev.filter(s => s.id !== id));
      toast.success('Scan deleted');
    } catch { toast.error('Failed to delete scan'); }
  };

  const exportAll = async () => {
    setExportingAll(true);
    try {
      const res  = await axios.get('/admin/vapt/network/export');
      const blob = new Blob([JSON.stringify(res.data.data,null,2)],{type:'application/json'});
      Object.assign(document.createElement('a'),{href:URL.createObjectURL(blob),download:`network-vapt-${new Date().toISOString().slice(0,10)}.json`}).click();
      toast.success('Exported!');
    } catch { toast.error('Export failed'); }
    finally { setExportingAll(false); }
  };

  const downloadReport = async (scan) => {
    setReportId(scan.id);
    try {
      const res = await axios.get(`/admin/vapt/network/export/scan/${scan.id}/pdf`,{responseType:'blob'});
      Object.assign(document.createElement('a'),{href:URL.createObjectURL(new Blob([res.data],{type:'application/pdf'})),download:`VAPT-${scan.target}-${scan.date}.pdf`}).click();
      toast.success('Report downloaded!');
    } catch { toast.error('Failed to generate report'); }
    finally { setReportId(null); }
  };

  const previewReport = async (scanId, target, date) => {
    setPreviewId(scanId);
    try {
      const res = await axios.get(`/admin/vapt/network/export/scan/${scanId}/pdf`,{responseType:'blob'});
      Object.assign(document.createElement('a'),{href:URL.createObjectURL(new Blob([res.data],{type:'application/pdf'})),download:`VAPT-${target}-${date}.pdf`}).click();
      toast.success('Report downloaded!');
    } catch { toast.error('Failed'); }
    finally { setPreviewId(null); }
  };

  const approveEmail = async (id) => {
    setApprovingId(id);
    try {
      const res = await axios.post(`/admin/vapt/email-approvals/${id}/approve`);
      toast.success(res.data?.message ?? 'Report sent to owner!');
      setApprovals(prev => prev.filter(a => a.id !== id));
    } catch (err) { toast.error(err.response?.data?.message ?? 'Failed to send'); }
    finally { setApprovingId(null); }
  };

  const rejectEmail = async (id) => {
    const note = prompt('Rejection reason (optional):') ?? '';
    try {
      await axios.post(`/admin/vapt/email-approvals/${id}/reject`,{note});
      toast.success('Request rejected.');
      setApprovals(prev => prev.filter(a => a.id !== id));
    } catch { toast.error('Failed to reject'); }
  };

  // Derived
  const activeScans  = scans.filter(s => s.status==='running'||s.status==='queued');
  const historyScans = scans.filter(s => s.status!=='running'&&s.status!=='queued');
  const openCritical = vulns.filter(v => v.severity==='critical'&&v.status==='open').length;
  const resolvedCnt  = vulns.filter(v => v.status==='resolved').length;
  const filteredVulns = vulns.filter(v =>
    (filterSev==='all'||v.severity===filterSev) &&
    (filterStatus==='all'||v.status===filterStatus) &&
    (!vulnSearch.trim() ||
      v.title?.toLowerCase().includes(vulnSearch.toLowerCase()) ||
      v.host?.toLowerCase().includes(vulnSearch.toLowerCase()) ||
      v.cve_id?.toLowerCase().includes(vulnSearch.toLowerCase()) ||
      v.service?.toLowerCase().includes(vulnSearch.toLowerCase()))
  );
  const uniqueUsers = [...new Map(scans.filter(s=>s.user).map(s=>[s.user,{name:s.user,email:s.email}])).values()];
  const totalRisk   = vulns.filter(v=>v.severity==='critical').length*4+vulns.filter(v=>v.severity==='high').length*3+vulns.filter(v=>v.severity==='medium').length*2+vulns.filter(v=>v.severity==='low').length;
  const riskLabel   = totalRisk===0?'Secure':totalRisk<5?'Low Risk':totalRisk<15?'Moderate':totalRisk<30?'High Risk':'Critical';
  const riskStyle   = totalRisk===0?{color:'#34d399'}:totalRisk<5?{color:'#38bdf8'}:totalRisk<15?{color:'#fbbf24'}:totalRisk<30?{color:'#fb923c'}:{color:'#f87171'};

  return (
    <div className="min-h-screen bg-[#0f1623] px-6 py-8 space-y-6 w-full">
      {refreshing && (
        <div className="fixed top-0 left-0 right-0 z-50 h-1 overflow-hidden" style={{background:'#1e2a3a'}}>
          <div className="h-full bg-cyan-500" style={{width:'60%',animation:'ind 1.2s ease-in-out infinite'}}/>
        </div>
      )}
      <style>{`@keyframes ind{0%{transform:translateX(-100%) scaleX(.4)}50%{transform:translateX(0) scaleX(.8)}100%{transform:translateX(100%) scaleX(.4)}}`}</style>

      {/* HEADER */}
      <div className="flex items-start justify-between gap-6 flex-wrap">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse"/>
            <span className="text-cyan-400 text-sm font-semibold tracking-widest uppercase">Admin Panel</span>
          </div>
          <h1 className="text-white text-4xl font-bold tracking-tight leading-none">Network VAPT</h1>
          <p className="text-gray-400 text-base mt-2">All users · All scans · Full control</p>
        </div>
        <div className="flex items-center gap-3 flex-wrap pt-1">
          {activeScans.length > 0 && (
            <div className="flex items-center gap-2 text-cyan-400 text-sm bg-cyan-500/10 border border-cyan-500/20 px-4 py-2 rounded-xl">
              <Radio size={13} className="animate-pulse"/> {activeScans.length} scan{activeScans.length!==1?'s':''} live
            </div>
          )}
          {error && (
            <div className="flex items-center gap-2 text-red-400 text-sm bg-red-500/10 border border-red-500/20 px-4 py-2 rounded-xl">
              <XCircle size={13}/> Error — <button onClick={()=>{setError(false);fetchData();}} className="underline">retry</button>
            </div>
          )}
          <button onClick={()=>fetchData()} disabled={refreshing}
            className="flex items-center gap-2 text-sm text-gray-400 hover:text-white px-4 py-2 rounded-xl border transition"
            style={{background:'rgba(255,255,255,0.03)',borderColor:'#1e2d42'}}>
            <RefreshCw size={14} className={refreshing?'animate-spin':''}/> Refresh
          </button>
          <button onClick={exportAll} disabled={exportingAll}
            className="flex items-center gap-2 text-sm px-4 py-2 rounded-xl border transition font-semibold"
            style={{color:'#22d3ee',background:'rgba(6,182,212,0.08)',borderColor:'rgba(6,182,212,0.25)'}}>
            {exportingAll?<Loader2 size={14} className="animate-spin"/>:<Download size={14}/>} Export All
          </button>
        </div>
      </div>

      {/* STAT CARDS */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-5">
        {[
          {icon:Activity,    label:'Active Scans',  value:activeScans.length, sev:null,       sub:'Currently running'       },
          {icon:ShieldAlert, label:'Open Critical', value:openCritical,        sev:'critical', sub:'Needs immediate action'  },
          {icon:Shield,      label:'Total Findings',value:vulns.length,        sev:'high',     sub:'Across all users'        },
          {icon:ShieldCheck, label:'Auto-Resolved', value:resolvedCnt,         sev:'low',      sub:'Resolved by clean rescan'},
        ].map(({icon:Icon, label, value, sev, sub}) => {
          const m = sev ? SEV[sev] : null;
          return (
            <div key={label} className="rounded-2xl p-6 flex flex-col gap-4"
              style={{background:'#151f2e',border:'1px solid #1e2d42'}}>
              <div className="flex items-center justify-between">
                <div className="w-11 h-11 rounded-2xl flex items-center justify-center"
                  style={{background: m?.bg??'rgba(6,182,212,0.1)', border:`1px solid ${m?.border??'rgba(6,182,212,0.25)'}`}}>
                  <Icon size={20} style={{color: m?.color??'#22d3ee'}}/>
                </div>
                <span className="w-3 h-3 rounded-full" style={{background: value>0?(m?.dot??'#22d3ee'):'#374151'}}/>
              </div>
              <div>
                <p className="text-white text-5xl font-bold leading-none">{value}</p>
                <p className="text-base font-semibold mt-2" style={{color: m?.color??'#22d3ee'}}>{label}</p>
                <p className="text-gray-500 text-sm mt-1">{sub}</p>
              </div>
              <div className="flex items-center justify-between pt-2 border-t" style={{borderColor:'#1e2d42'}}>
                <span className="text-gray-600 text-sm">{scans.length} total scans</span>
                <span className="text-sm font-bold" style={riskStyle}>{riskLabel}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* TABS */}
      <div className="flex gap-1 p-1.5 rounded-2xl w-fit" style={{background:'#151f2e',border:'1px solid #1e2d42'}}>
        {['scans','vulnerabilities','approvals','users'].map(tab => (
          <button key={tab} onClick={()=>setActiveTab(tab)}
            className="px-5 py-2.5 rounded-xl text-sm font-semibold capitalize transition"
            style={{background:activeTab===tab?'#1e2d42':'transparent', color:activeTab===tab?'#fff':'#6b7280'}}>
            {tab}
            {tab==='scans'     && activeScans.length>0 && <span className="ml-2 w-2.5 h-2.5 inline-block rounded-full bg-cyan-400 animate-pulse"/>}
            {tab==='approvals' && approvals.length>0   && <span className="ml-2 text-xs bg-amber-500 text-black font-bold px-1.5 py-0.5 rounded-full">{approvals.length}</span>}
          </button>
        ))}
      </div>

      {/* ══ SCANS TAB ══ */}
      {activeTab==='scans' && (
        <div className="grid md:grid-cols-5 gap-5 items-start">
          {activeScans.length > 0 && (
            <Card className="md:col-span-2" style={{border:'1px solid rgba(6,182,212,0.3)'}}>
              <CardHeader>
                <Activity size={16} className="text-cyan-400"/>
                <span className="text-white font-semibold text-base">Active Scans</span>
                <span className="text-cyan-400 text-sm ml-auto">{activeScans.length} live</span>
              </CardHeader>
              <div>{activeScans.map(s=><ScanRow key={s.id} scan={s} onDelete={deleteScan} onReport={downloadReport} loadingId={reportId}/>)}</div>
            </Card>
          )}
          <Card className={activeScans.length>0?'md:col-span-3':'md:col-span-5'}>
            <CardHeader>
              <Clock size={16} className="text-gray-400"/>
              <span className="text-white font-semibold text-base">Scan History</span>
              <span className="text-gray-500 text-sm ml-auto">{historyScans.length} scans</span>
            </CardHeader>
            <div className="px-4 py-2.5" style={{borderBottom:'1px solid #1e2d42'}}>
              <input
                type="text"
                value={scanSearch}
                onChange={e => setScanSearch(e.target.value)}
                placeholder="Search by IP, network or user..."
                className="w-full text-white text-sm px-3 py-2 rounded-lg placeholder:text-gray-600 focus:outline-none focus:ring-1 focus:ring-cyan-500/30 transition"
                style={{background:'#0f1623', border:'1px solid #1e2d42'}}
              />
            </div>
            {historyScans.length===0
              ? <div className="text-center py-16"><Clock size={28} className="mx-auto mb-3 text-gray-800"/><p className="text-base text-gray-600">No completed scans yet.</p></div>
              : <div className="overflow-y-auto" style={{maxHeight:520}}>
                  {historyScans
                    .filter(s => !scanSearch.trim() ||
                      s.target?.toLowerCase().includes(scanSearch.toLowerCase()) ||
                      s.user?.toLowerCase().includes(scanSearch.toLowerCase()))
                    .map(s=><ScanRow key={s.id} scan={s} onDelete={deleteScan} onReport={downloadReport} loadingId={reportId}/>)
                  }
                </div>
            }
          </Card>
        </div>
      )}

      {/* ══ VULNERABILITIES TAB ══ */}
      {activeTab==='vulnerabilities' && (
        <Card>
          <CardHeader>
            <Shield size={16} className="text-gray-400"/>
            <span className="text-white font-semibold text-base">All Vulnerability Findings</span>
            <div className="flex gap-2 ml-3">
              {['all','critical','high','medium','low'].map(s => {
                const m = SEV[s];
                return (
                  <button key={s} onClick={()=>setFilterSev(s)}
                    className="px-3 py-1.5 rounded-xl text-sm font-semibold capitalize transition"
                    style={{color:filterSev===s?(s==='all'?'#fff':m?.color):'#6b7280', background:filterSev===s?(s==='all'?'#374151':(m?.bg??'rgba(255,255,255,0.05)')):'transparent', border:`1px solid ${filterSev===s?(s==='all'?'#4b5563':(m?.border??'#2d3748')):'transparent'}`}}>
                    {s}
                  </button>
                );
              })}
            </div>
            <div className="h-5 w-px mx-1" style={{background:'#1e2d42'}}/>
            <div className="flex gap-2">
              {['all','open','resolved'].map(s=>(
                <button key={s} onClick={()=>setFilterStatus(s)}
                  className="px-3 py-1.5 rounded-xl text-sm font-semibold capitalize transition"
                  style={{color:filterStatus===s?'#fff':'#6b7280', background:filterStatus===s?'#374151':'transparent', border:`1px solid ${filterStatus===s?'#4b5563':'transparent'}`}}>
                  {s}
                </button>
              ))}
            </div>
            <span className="text-gray-500 text-sm ml-auto">{filteredVulns.length} finding{filteredVulns.length!==1?'s':''}</span>
          </CardHeader>
          <div className="px-4 py-2.5" style={{borderBottom:'1px solid #1e2d42'}}>
            <input
              type="text"
              value={vulnSearch}
              onChange={e => setVulnSearch(e.target.value)}
              placeholder="Search by title, host, CVE ID or service..."
              className="w-full text-white text-sm px-3 py-2 rounded-lg placeholder:text-gray-600 focus:outline-none focus:ring-1 focus:ring-cyan-500/30 transition"
              style={{background:'#0f1623', border:'1px solid #1e2d42'}}
            />
          </div>

          {filteredVulns.length===0
            ? <div className="text-center py-20"><Shield size={36} className="mx-auto mb-4 text-gray-800"/><p className="text-lg text-gray-500">{vulns.length===0?'No vulnerabilities found.':'No findings match filters.'}</p><p className="text-sm text-gray-600 mt-1">Vulnerabilities auto-resolve when the network is rescanned and comes back clean.</p></div>
            : (
              <div className="overflow-y-auto" style={{maxHeight:640}}>
                <div className="divide-y" style={{borderColor:'#1e2d42'}}>
                  {filteredVulns.map(v => {
                    const m = SEV[v.severity] ?? SEV.low;
                    const isOpen = expandedVulns.has(v.id);
                    const toggle = () => setExpandedVulns(p => { const n=new Set(p); n.has(v.id)?n.delete(v.id):n.add(v.id); return n; });
                    return (
                      <div key={v.id} style={{background:isOpen?'rgba(255,255,255,0.015)':'transparent'}} className="transition-colors">
                        <div className="flex items-center gap-4 px-6 py-5">
                          <button onClick={toggle} className="flex items-center gap-4 flex-1 text-left min-w-0">
                            {/* CVSS score box */}
                            <div className="w-16 h-16 rounded-2xl flex items-center justify-center flex-shrink-0"
                              style={{background:m.bg, border:`1.5px solid ${m.border}`}}>
                              <span className="text-xl font-bold font-mono" style={{color:m.color}}>{v.cvss}</span>
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 mb-2 flex-wrap">
                                <SevBadge severity={v.severity}/>
                                {v.cve_id && (
                                  <span className="text-sm font-mono px-2.5 py-1 rounded-lg"
                                    style={{color:'#818cf8', background:'rgba(129,140,248,0.1)', border:'1px solid rgba(129,140,248,0.25)'}}>
                                    {v.cve_id}
                                  </span>
                                )}
                                <span className="text-sm px-2.5 py-1 rounded-lg font-semibold"
                                  style={v.status==='open'?{color:'#f87171',background:'rgba(248,113,113,0.1)',border:'1px solid rgba(248,113,113,0.25)'}:{color:'#34d399',background:'rgba(52,211,153,0.1)',border:'1px solid rgba(52,211,153,0.25)'}}>
                                  {v.status==='open'?'Open':'Resolved'}
                                </span>
                                {v.user && <span className="text-gray-500 text-sm flex items-center gap-1"><Users size={11}/>{v.user}</span>}
                              </div>
                              <p className="text-white text-base font-semibold truncate">{v.title}</p>
                              <p className="text-gray-400 text-sm mt-1 font-mono">{v.host}:{v.port} · {v.service}</p>
                            </div>
                          </button>
                          <div className="flex items-center gap-2 flex-shrink-0">
                            <button onClick={toggle} className="p-2 text-gray-500 rounded-xl hover:bg-white/5 transition">
                              {isOpen?<ChevronUp size={16}/>:<ChevronDown size={16}/>}
                            </button>
                            {v.status === 'open' && (
                              <button onClick={()=>markResolved(v.id)}
                                className="p-2 rounded-xl text-gray-600 hover:text-emerald-400 hover:bg-emerald-500/10 transition" title="Mark as resolved">
                                <CheckCircle2 size={16}/>
                              </button>
                            )}
                            <button onClick={()=>deleteVuln(v.id)}
                              className="p-2 rounded-xl text-gray-600 hover:text-red-400 hover:bg-red-500/10 transition" title="Delete false positive">
                              <Trash2 size={16}/>
                            </button>
                          </div>
                        </div>
                        {isOpen && (
                          <div className="px-6 pb-6 pt-2 space-y-4" style={{borderTop:'1px solid #1e2d42'}}>
                            <div className="grid grid-cols-3 gap-4">
                              {[{label:'Host',value:v.host},{label:'Port / Service',value:`${v.port} / ${v.service}`},{label:'CVSS Score',value:`${v.cvss} / 10.0`,color:m.color}].map(f=>(
                                <div key={f.label} className="px-5 py-4 rounded-2xl" style={{background:'#0f1623',border:'1px solid #1e2d42'}}>
                                  <p className="text-gray-500 text-xs uppercase tracking-widest font-semibold mb-2">{f.label}</p>
                                  <p className="text-base font-bold font-mono" style={{color:f.color??'#fff'}}>{f.value}</p>
                                </div>
                              ))}
                            </div>
                            {v.description && (
                              <div className="px-5 py-4 rounded-2xl" style={{background:'#0f1623',border:'1px solid #1e2d42'}}>
                                <p className="text-gray-500 text-xs uppercase tracking-widest font-semibold mb-2">Description</p>
                                <p className="text-gray-300 text-sm leading-relaxed">{v.description}</p>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )
          }
        </Card>
      )}

      {/* ══ APPROVALS TAB ══ */}
      {activeTab==='approvals' && (
        <Card>
          <CardHeader>
            <span className="text-lg">✉</span>
            <span className="text-white font-semibold text-base">Pending Email Approvals</span>
            {approvals.length>0 && <span className="text-xs bg-amber-500 text-black font-bold px-2 py-0.5 rounded-full">{approvals.length}</span>}
            <p className="text-gray-500 text-sm ml-auto">Review report before sending to network owner</p>
          </CardHeader>
          {approvals.length===0 ? (
            <div className="text-center py-20">
              <div className="text-5xl mb-4">✉</div>
              <p className="text-lg text-gray-500">No pending approvals.</p>
              <p className="text-sm text-gray-600 mt-1">Email requests from users will appear here for your review.</p>
            </div>
          ) : (
            <div className="divide-y" style={{borderColor:'#1e2d42'}}>
              {approvals.map(a => (
                <div key={a.id} className="px-6 py-6 hover:bg-white/[0.01] transition-colors">
                  <div className="flex items-start gap-6 flex-wrap">
                    <div className="flex-1 min-w-0 space-y-4">
                      {/* Header */}
                      <div className="flex items-center gap-3 flex-wrap">
                        <span className="text-sm font-bold px-3 py-1 rounded-lg"
                          style={{color:'#fbbf24',background:'rgba(251,191,36,0.1)',border:'1px solid rgba(251,191,36,0.25)'}}>
                          ⏳ Pending Approval
                        </span>
                        <span className="text-white font-mono font-bold text-xl">{a.target}</span>
                        <span className="text-gray-500 text-sm">{new Date(a.created_at).toLocaleDateString()}</span>
                      </div>
                      {/* Info grid */}
                      <div className="grid grid-cols-2 gap-4">
                        <div className="px-5 py-4 rounded-2xl" style={{background:'#0f1623',border:'1px solid #1e2d42'}}>
                          <p className="text-gray-500 text-xs uppercase tracking-widest font-semibold mb-2">Requested By</p>
                          <p className="text-white font-semibold text-base">{a.requested_by}</p>
                          <p className="text-gray-500 text-sm mt-0.5">{a.user_email}</p>
                        </div>
                        <div className="px-5 py-4 rounded-2xl" style={{background:'rgba(167,139,250,0.06)',border:'1px solid rgba(167,139,250,0.3)'}}>
                          <p className="text-purple-400 text-xs uppercase tracking-widest font-semibold mb-2">📨 Report Will Be Sent To</p>
                          <p className="text-purple-200 font-bold text-base">{a.owner_name || 'Network Owner'}</p>
                          <p className="text-purple-400 font-mono text-sm mt-0.5">{a.owner_email}</p>
                        </div>
                      </div>
                      {/* Findings summary */}
                      <div className="flex gap-2 flex-wrap">
                        {a.vuln_count===0 ? (
                          <span className="text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-3 py-1.5 rounded-xl text-sm font-semibold flex items-center gap-2">
                            <Shield size={14}/> Clean scan — no vulnerabilities
                          </span>
                        ) : (
                          <>
                            {a.critical>0 && <span style={{color:'#f87171',background:'rgba(248,113,113,0.1)',border:'1px solid rgba(248,113,113,0.25)'}} className="px-3 py-1.5 rounded-xl text-sm font-bold">{a.critical} Critical</span>}
                            {a.high>0     && <span style={{color:'#fb923c',background:'rgba(251,146,60,0.1)', border:'1px solid rgba(251,146,60,0.25)'}} className="px-3 py-1.5 rounded-xl text-sm font-bold">{a.high} High</span>}
                            <span className="text-gray-500 text-sm self-center">{a.vuln_count} total finding{a.vuln_count!==1?'s':''}</span>
                          </>
                        )}
                      </div>
                    </div>
                    {/* Action buttons */}
                    <div className="flex flex-col gap-3 flex-shrink-0" style={{minWidth:160}}>
                      <button onClick={()=>previewReport(a.scan_id,a.target,new Date(a.created_at).toISOString().slice(0,10))}
                        disabled={previewId===a.scan_id}
                        className="flex items-center justify-center gap-2 text-sm px-4 py-2.5 rounded-xl border font-semibold transition"
                        style={{color:'#22d3ee',background:'rgba(6,182,212,0.08)',borderColor:'rgba(6,182,212,0.25)'}}>
                        {previewId===a.scan_id?<Loader2 size={13} className="animate-spin"/>:<Download size={13}/>} Preview Report
                      </button>
                      <button onClick={()=>approveEmail(a.id)} disabled={approvingId===a.id}
                        className="flex items-center justify-center gap-2 text-sm px-4 py-2.5 rounded-xl border font-semibold transition disabled:opacity-60"
                        style={{color:'#4ade80',background:'rgba(74,222,128,0.08)',borderColor:'rgba(74,222,128,0.3)'}}>
                        {approvingId===a.id?<Loader2 size={13} className="animate-spin"/>:<CheckCircle2 size={14}/>}
                        {approvingId===a.id?'Sending...':'Approve & Send'}
                      </button>
                      <button onClick={()=>rejectEmail(a.id)}
                        className="flex items-center justify-center gap-2 text-sm px-4 py-2.5 rounded-xl border font-semibold transition"
                        style={{color:'#f87171',background:'rgba(248,113,113,0.08)',borderColor:'rgba(248,113,113,0.3)'}}>
                        <XCircle size={14}/> Reject
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      )}

      {/* ══ USERS TAB ══ */}
      {activeTab==='users' && (
        <Card>
          <CardHeader>
            <Users size={16} className="text-gray-400"/>
            <span className="text-white font-semibold text-base">Users &amp; Scan Activity</span>
            <span className="text-gray-500 text-sm ml-auto">{uniqueUsers.length} users</span>
          </CardHeader>
          {uniqueUsers.length===0
            ? <div className="text-center py-16"><Users size={28} className="mx-auto mb-3 text-gray-800"/><p className="text-base text-gray-600">No users found.</p></div>
            : (
              <div className="divide-y" style={{borderColor:'#1e2d42'}}>
                {uniqueUsers.map(u => {
                  const us   = scans.filter(s=>s.user===u.name);
                  const uv   = vulns.filter(v=>v.user===u.name);
                  const live = us.some(s=>s.status==='running'||s.status==='queued');
                  const open = uv.filter(v=>v.status==='open').length;
                  const crit = uv.filter(v=>v.severity==='critical'&&v.status==='open').length;
                  return (
                    <div key={u.name} className="px-6 py-5 hover:bg-white/[0.01] transition-colors">
                      <div className="flex items-center gap-5">
                        <div className="relative flex-shrink-0">
                          <div className="w-12 h-12 rounded-2xl bg-cyan-700 flex items-center justify-center text-white font-bold text-lg">
                            {u.name?.[0]?.toUpperCase()}
                          </div>
                          {live && <span className="absolute -top-0.5 -right-0.5 w-3.5 h-3.5 rounded-full bg-cyan-400 border-2 border-[#151f2e] animate-pulse"/>}
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-white font-semibold text-base">{u.name}</p>
                          <p className="text-gray-500 text-sm mt-0.5">{u.email}</p>
                        </div>
                        <div className="flex gap-8 text-center">
                          {[
                            {label:'Scans',    value:us.length,       color:'#fff'   },
                            {label:'Open',     value:open,            color:open>0?'#fb923c':'#374151'},
                            {label:'Critical', value:crit,            color:crit>0?'#f87171':'#374151'},
                            {label:'Status',   value:live?'Live':'—', color:live?'#22d3ee':'#374151' },
                          ].map(f=>(
                            <div key={f.label}>
                              <p className="font-bold text-2xl leading-none" style={{color:f.color}}>{f.value}</p>
                              <p className="text-gray-600 text-xs mt-1 uppercase tracking-wide">{f.label}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )
          }
        </Card>
      )}
    </div>
  );
}