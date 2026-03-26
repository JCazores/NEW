import { useState, useEffect, useMemo } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  MonitorCheck, AlertCircle, Activity, ExternalLink,
  TrendingUp, TrendingDown, Shield, Zap, Clock, RefreshCw
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Cell,
} from 'recharts';
import StatusBadge from '../../components/shared/StatusBadge';
import StatsChart from '../../components/charts/StatsChart';
import { getUserMonitors, getUserIncidents } from '../../api/userApi';
import api from '../../api/axios';
import { usePeriodStore } from '../../store/periodStore';

// ── palette & helpers ─────────────────────────────────────────────────────────
const PALETTE = ['#10b981','#3b82f6','#8b5cf6','#f59e0b','#ef4444','#06b6d4','#ec4899'];

const MonitorTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  const color = payload[0]?.payload?._color || '#10b981';
  return (
    <div style={{
      background: 'rgba(13,18,30,0.97)', border: `1px solid ${color}50`,
      borderRadius: 12, padding: '12px 16px',
      boxShadow: `0 8px 32px rgba(0,0,0,.6), 0 0 20px ${color}20`,
    }}>
      <p style={{ color: '#64748b', fontSize: 11, marginBottom: 6 }}>{label}</p>
      <p style={{ color, fontWeight: 800, fontSize: 22, lineHeight: 1 }}>{payload[0].value}</p>
      <p style={{ color: '#334155', fontSize: 10, marginTop: 4 }}>incidents</p>
    </div>
  );
};

const RoundBar = ({ x, y, width, height, color }) => {
  if (!height || height <= 0) return null;
  const r   = Math.min(5, width / 2);
  const gId = `ubg-${(color || '').replace('#', '')}`;
  return (
    <g>
      <defs>
        <linearGradient id={gId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   stopColor={color} stopOpacity={0.95} />
          <stop offset="100%" stopColor={color} stopOpacity={0.2}  />
        </linearGradient>
      </defs>
      <path
        d={`M${x+r},${y} H${x+width-r} Q${x+width},${y} ${x+width},${y+r} V${y+height} H${x} V${y+r} Q${x},${y} ${x+r},${y} Z`}
        fill={`url(#${gId})`}
        style={{ filter: `drop-shadow(0 0 6px ${color}60)` }}
      />
      <rect x={x+1} y={y} width={width-2} height={3} rx={r} fill={color}
        style={{ filter: `drop-shadow(0 0 4px ${color})` }} />
    </g>
  );
};

const CustomXTick = ({ x, y, payload }) => (
  <g transform={`translate(${x},${y})`}>
    <text x={0} y={0} dy={14} textAnchor="middle" fill="#475569" fontSize={11}>
      {payload.value?.length > 12 ? payload.value.slice(0, 12) + '…' : payload.value}
    </text>
  </g>
);

const PERIODS = [
  { value: 'hour',  label: 'Hour'  },
  { value: 'day',   label: '24h'   },
  { value: 'week',  label: 'Week'  },
  { value: 'month', label: 'Month' },
];

// ── Incidents by Monitor chart ────────────────────────────────────────────────
function IncidentsByMonitorChart({ incidents, period, onPeriodChange }) {
  const cutoffs = {
    hour:  new Date(Date.now() - 1   * 3600 * 1000),
    day:   new Date(Date.now() - 24  * 3600 * 1000),
    week:  new Date(Date.now() - 7   * 24 * 3600 * 1000),
    month: new Date(Date.now() - 30  * 24 * 3600 * 1000),
  };

  const chartData = useMemo(() => {
    const filtered = incidents.filter(i => new Date(i.started_at) >= cutoffs[period]);
    const map = {};
    filtered.forEach(i => { const name = i.monitor?.name || 'Unknown'; map[name] = (map[name] || 0) + 1; });
    return Object.entries(map)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 7)
      .map(([name, count], i) => ({ name, count, _color: PALETTE[i % PALETTE.length] }));
  }, [incidents, period]);

  return (
    <div style={{
      background: 'linear-gradient(160deg, #0f1623 0%, #111827 100%)',
      border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: 20, padding: '22px 22px 20px',
      position: 'relative', overflow: 'hidden',
    }}>
      <div style={{
        position: 'absolute', bottom: -20, left: '50%', transform: 'translateX(-50%)',
        width: 200, height: 80,
        background: 'radial-gradient(ellipse, #10b98115 0%, transparent 70%)',
        pointerEvents: 'none',
      }} />
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
        <div>
          <p style={{ color: '#334155', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 4 }}>BREAKDOWN</p>
          <h3 style={{ color: '#e2e8f0', fontSize: 15, fontWeight: 700, margin: 0 }}>Incidents by Monitor</h3>
        </div>
        <div style={{ display: 'flex', gap: 2, background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 10, padding: 3 }}>
          {PERIODS.map(p => (
            <button key={p.value} onClick={() => onPeriodChange(p.value)} style={{
              padding: '4px 10px', borderRadius: 7, border: 'none', cursor: 'pointer',
              fontSize: 11, fontWeight: 700, transition: 'all .2s',
              background: period === p.value ? '#10b981' : 'transparent',
              color:      period === p.value ? '#000'    : '#4b5563',
              boxShadow:  period === p.value ? '0 0 14px #10b98170' : 'none',
            }}>{p.label}</button>
          ))}
        </div>
      </div>
      {chartData.length > 0 ? (
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={chartData} margin={{ top: 10, right: 8, left: -20, bottom: 10 }}>
            <CartesianGrid stroke="rgba(255,255,255,0.05)" strokeDasharray="4 4" vertical={false} />
            <XAxis dataKey="name" tick={<CustomXTick />} axisLine={{ stroke: 'rgba(255,255,255,0.08)' }} tickLine={false} interval={0} height={40} />
            <YAxis tick={{ fill: '#475569', fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} />
            <Tooltip content={<MonitorTooltip />} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
            <Bar dataKey="count" maxBarSize={48}
              shape={(props) => {
                const idx   = chartData.findIndex(d => d.name === props.name);
                const color = PALETTE[(idx >= 0 ? idx : 0) % PALETTE.length];
                return <RoundBar {...props} color={color} />;
              }}>
              {chartData.map((_, i) => <Cell key={i} fill={PALETTE[i % PALETTE.length]} />)}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      ) : (
        <div style={{ height: 300, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 10 }}>
          <div style={{ display: 'flex', gap: 4, alignItems: 'flex-end', opacity: 0.2 }}>
            {[18, 30, 12, 24, 10].map((h, i) => (
              <div key={i} style={{ width: 8, height: h, background: PALETTE[i], borderRadius: '3px 3px 0 0' }} />
            ))}
          </div>
          <p style={{ color: '#1e293b', fontSize: 13, fontWeight: 500 }}>No incidents for this period</p>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────

export default function UserDashboard() {
  const [monitors,       setMonitors]       = useState([]);
  const [incidents,      setIncidents]      = useState([]);
  const [monitorStats,   setMonitorStats]   = useState([]);
  const [incidentStats,  setIncidentStats]  = useState([]);
  const [loading,        setLoading]        = useState(true);
  const [lastUpdated,    setLastUpdated]    = useState(null);
  const [monitorFilter,  setMonitorFilter]  = useState('active');
  const [monitorSort,    setMonitorSort]    = useState('default');

  const navigate = useNavigate();
  const { monitorPeriod, incidentPeriod, causePeriod, setPeriod } = usePeriodStore();

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => { fetchMonitorStats();  }, [monitorPeriod]);
  useEffect(() => { fetchIncidentStats(); }, [incidentPeriod]);

  const fetchData = async () => {
    try {
      const [mRes, iRes] = await Promise.all([
        getUserMonitors(),
        getUserIncidents({ per_page: 200 }),
      ]);
      setMonitors(mRes.data.data  || []);
      setIncidents(iRes.data.data || []);
      setLastUpdated(new Date());
    } catch (err) { console.error(err); }
    finally { setLoading(false); }
  };

  const fetchMonitorStats  = async () => { try { const r = await api.get(`/user/monitor-stats?period=${monitorPeriod}`);   setMonitorStats(r.data.data   || []); } catch {} };
  const fetchIncidentStats = async () => { try { const r = await api.get(`/user/incident-stats?period=${incidentPeriod}`); setIncidentStats(r.data.data  || []); } catch {} };

  const activeMonitors = monitors.filter(m => m.is_active !== false);

  const avgUptime = (() => {
    const vals = monitors.map(m => Number(m.uptime_percentage)).filter(v => isFinite(v));
    return vals.length ? Number((vals.reduce((a, b) => a + b, 0) / vals.length).toFixed(2)) : 0;
  })();

  const monitorsForCard = (monitorFilter === 'all' ? monitors : activeMonitors)
    .slice()
    .sort((a, b) => {
      if (monitorSort === 'default') return 0;
      const rank = (s, upFirst) => { const v = (s||'').toLowerCase(); return upFirst ? (v==='up'?0:1) : (v==='down'?0:1); };
      const ra = rank(a.last_status, monitorSort === 'asc');
      const rb = rank(b.last_status, monitorSort === 'asc');
      return ra !== rb ? ra - rb : (a.name||'').localeCompare(b.name||'');
    });

  const openCount     = incidents.filter(i => i.status === 'open').length;
  const resolvedCount = incidents.filter(i => i.status === 'resolved').length;

  const statCards = [
    { label:'Total Monitors',     value:monitors.length,  icon:MonitorCheck, color:'#10b981', link:'/user/monitors',                  sub:`${activeMonitors.length} active` },
    { label:'Avg Uptime',         value:`${avgUptime}%`,  icon:Activity,     color:'#10b981', link:'/user/monitors',                  sub:'across all monitors' },
    { label:'Active Incidents',   value:openCount,        icon:AlertCircle,  color:openCount>0?'#ef4444':'#10b981', link:'/user/incidents?status=open',     sub:openCount>0?'needs attention':'all clear' },
    { label:'Resolved Incidents', value:resolvedCount,    icon:TrendingUp,   color:'#3b82f6', link:'/user/incidents?status=resolved', sub:'total resolved' },
  ];

  if (loading) return (
    <div className="flex items-center justify-center min-h-screen bg-gray-950">
      <div className="text-center">
        <div className="relative w-14 h-14 mx-auto mb-5">
          <div className="absolute inset-0 rounded-full border border-gray-800" />
          <div className="absolute inset-0 rounded-full border border-t-emerald-400 border-r-emerald-400/20 border-b-transparent border-l-transparent animate-spin" />
          <div className="absolute inset-3 rounded-full bg-emerald-400/10 flex items-center justify-center">
            <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          </div>
        </div>
        <p className="text-gray-400 text-sm font-medium">Initializing dashboard...</p>
        <p className="text-gray-600 text-xs mt-1">Connecting to monitors</p>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gray-950 p-8">
      <style>{`
        @keyframes fadeUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
        .fu-0{animation:fadeUp .35s ease both 0s}
        .fu-1{animation:fadeUp .35s ease both .06s}
        .fu-2{animation:fadeUp .35s ease both .12s}
        .fu-3{animation:fadeUp .35s ease both .18s}
        .fu-4{animation:fadeUp .35s ease both .24s}
        .scard{transition:transform .2s,box-shadow .2s}
        .scard:hover{transform:translateY(-3px)}
        .mrow,.irow{transition:all .15s}
        .slim::-webkit-scrollbar{width:3px}
        .slim::-webkit-scrollbar-track{background:transparent}
        .slim::-webkit-scrollbar-thumb{background:#1f2937;border-radius:4px}
        .slim::-webkit-scrollbar-thumb:hover{background:#374151}
      `}</style>

      {/* Header */}
      <div className="flex items-start justify-between mb-10 fu-0">
        <div>
          <div className="flex items-center gap-2.5 mb-3">
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inset-0 rounded-full bg-emerald-400 opacity-50" />
              <span className="relative rounded-full h-2.5 w-2.5 bg-emerald-400 inline-flex" style={{boxShadow:'0 0 8px #10b981'}} />
            </span>
            <span className="text-emerald-400 text-xs font-bold tracking-[.2em] uppercase">Live Monitoring</span>
          </div>
          <h1 className="text-4xl font-black text-white tracking-tight leading-none">Dashboard</h1>
          <p className="text-gray-500 text-sm mt-2">Overview of your assigned monitors and incidents</p>
        </div>
        <div className="flex items-center gap-2 px-4 py-2 rounded-xl border border-gray-800 bg-gray-900">
          <RefreshCw size={12} className="text-emerald-400 animate-spin" style={{animationDuration:'3s'}} />
          <span className="text-gray-400 text-xs">
            {lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString()}` : 'Syncing...'}
          </span>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {statCards.map((c, i) => (
          <Link key={i} to={c.link} className={`block scard fu-${i+1}`}>
            <div className="relative h-full rounded-2xl p-5 overflow-hidden"
              style={{background:'linear-gradient(145deg,#0f1623,#111827)',border:'1px solid rgba(255,255,255,0.07)'}}
              onMouseEnter={e=>{ e.currentTarget.style.borderColor=`${c.color}45`; e.currentTarget.style.boxShadow=`0 8px 40px ${c.color}12`; }}
              onMouseLeave={e=>{ e.currentTarget.style.borderColor='rgba(255,255,255,0.07)'; e.currentTarget.style.boxShadow='none'; }}
            >
              <div className="absolute -top-6 -right-6 w-20 h-20 rounded-full pointer-events-none"
                style={{background:`radial-gradient(circle,${c.color}22 0%,transparent 70%)`}} />
              <div className="flex items-center justify-between mb-5">
                <div className="p-2.5 rounded-xl" style={{background:`${c.color}15`,border:`1px solid ${c.color}22`}}>
                  <c.icon size={18} color={c.color} />
                </div>
                <div className="w-1.5 h-1.5 rounded-full" style={{background:c.color,boxShadow:`0 0 8px ${c.color}`}} />
              </div>
              <p className="text-[2rem] font-black text-white leading-none mb-1.5 tracking-tight"
                style={{textShadow:`0 0 30px ${c.color}30`}}>{c.value}</p>
              <p className="text-gray-400 text-xs font-semibold mb-1">{c.label}</p>
              <p className="text-gray-600 text-xs">{c.sub}</p>
              <div className="absolute bottom-0 left-4 right-4 h-px"
                style={{background:`linear-gradient(90deg,transparent,${c.color}40,transparent)`}} />
            </div>
          </Link>
        ))}
      </div>

      {/* Monitors + Incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">

        {/* Active Monitors */}
        <div className="rounded-2xl overflow-hidden fu-2"
          style={{background:'linear-gradient(160deg,#0f1623,#111827)',border:'1px solid rgba(255,255,255,0.07)'}}>
          <div className="px-6 py-5 flex items-center justify-between"
            style={{borderBottom:'1px solid rgba(255,255,255,0.06)',background:'rgba(255,255,255,0.015)'}}>
            <div>
              <h2 className="text-white font-bold text-lg leading-none mb-1">Active Monitors</h2>
              <p className="text-gray-500 text-xs">
                {monitorFilter==='all' ? monitors.length : activeMonitors.length}{' '}
                {monitorFilter==='all' ? 'total' : 'active'} monitors
              </p>
            </div>
            <div className="flex items-center gap-2">
              <select value={monitorFilter} onChange={e=>setMonitorFilter(e.target.value)}
                className="px-2.5 py-1.5 text-xs text-gray-300 rounded-lg outline-none cursor-pointer"
                style={{background:'#1a2232',border:'1px solid rgba(255,255,255,0.1)'}}>
                <option value="active">Active</option>
                <option value="all">All</option>
              </select>
              <select value={monitorSort} onChange={e=>setMonitorSort(e.target.value)}
                className="px-2.5 py-1.5 text-xs text-gray-300 rounded-lg outline-none cursor-pointer"
                style={{background:'#1a2232',border:'1px solid rgba(255,255,255,0.1)'}}>
                <option value="default">Sort</option>
                <option value="asc">Up first</option>
                <option value="desc">Down first</option>
              </select>
              <Link to="/user/monitors"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-white"
                style={{background:'linear-gradient(135deg,#059669,#10b981)',boxShadow:'0 0 16px #10b98140'}}>
                View All <ExternalLink size={11} />
              </Link>
            </div>
          </div>

          <div className="p-4 space-y-2.5 max-h-[500px] overflow-y-auto slim">
            {monitorsForCard.length === 0 ? (
              <div className="py-16 text-center">
                <div className="w-14 h-14 rounded-2xl flex items-center justify-center mx-auto mb-4"
                  style={{background:'rgba(255,255,255,0.04)',border:'1px solid rgba(255,255,255,0.08)'}}>
                  <MonitorCheck size={24} className="text-gray-600" />
                </div>
                <p className="text-gray-300 font-semibold text-sm">No monitors assigned yet</p>
                <p className="text-gray-600 text-xs mt-1">Contact your admin to get started</p>
              </div>
            ) : monitorsForCard.map(m => {
              const isUp = m.last_status === 'up';
              const ac   = isUp ? '#10b981' : '#ef4444';
              return (
                <div key={m.id}
                  onClick={() => {
                    const sortOrder = m.last_status === 'up' ? 'up_only' : 'down_only';
                    navigate(`/user/monitors?highlight=${m.id}&sortOrder=${sortOrder}&resetFilters=1`);
                  }}
                  className="mrow relative rounded-xl p-4 cursor-pointer"
                  style={{background:isUp?'rgba(16,185,129,0.05)':'rgba(239,68,68,0.05)',border:`1px solid ${isUp?'rgba(16,185,129,0.15)':'rgba(239,68,68,0.2)'}`}}
                  onMouseEnter={e=>{e.currentTarget.style.background=isUp?'rgba(16,185,129,0.09)':'rgba(239,68,68,0.09)';e.currentTarget.style.borderColor=isUp?'rgba(16,185,129,0.35)':'rgba(239,68,68,0.35)';}}
                  onMouseLeave={e=>{e.currentTarget.style.background=isUp?'rgba(16,185,129,0.05)':'rgba(239,68,68,0.05)';e.currentTarget.style.borderColor=isUp?'rgba(16,185,129,0.15)':'rgba(239,68,68,0.2)';}}
                >
                  <div className="absolute left-0 top-3 bottom-3 w-0.5 rounded-r"
                    style={{background:ac,boxShadow:`0 0 6px ${ac}`}} />
                  <div className="flex items-start justify-between gap-3 mb-3">
                    <div className="flex items-start gap-3 flex-1 min-w-0">
                      <StatusBadge status={m.last_status} />
                      <div className="flex-1 min-w-0">
                        <h3 className="text-white font-semibold text-sm truncate">{m.name}</h3>
                        <p className="text-gray-500 text-xs truncate mt-0.5">{m.url}</p>
                        {m.url.startsWith('https://') && m.ssl_days_remaining !== null && (
                          <span className={`text-xs flex items-center gap-1 mt-1 w-fit ${m.ssl_days_remaining<=7?'text-red-400':m.ssl_days_remaining<=30?'text-yellow-400':'text-emerald-400'}`}>
                            <Shield size={9} /> SSL {m.ssl_days_remaining}d
                          </span>
                        )}
                      </div>
                    </div>
                    <Link to={`/user/incidents?monitor=${m.id}`} onClick={e=>e.stopPropagation()}
                      className="text-xs px-2.5 py-1 rounded-lg text-gray-400 transition whitespace-nowrap"
                      style={{background:'rgba(255,255,255,0.06)',border:'1px solid rgba(255,255,255,0.1)'}}
                      onMouseEnter={e=>e.currentTarget.style.color='#e2e8f0'}
                      onMouseLeave={e=>e.currentTarget.style.color='#9ca3af'}>
                      Incidents
                    </Link>
                  </div>
                  <div className="grid grid-cols-3 gap-2 text-xs mb-2.5">
                    <div className="rounded-lg px-2.5 py-2" style={{background:'rgba(16,185,129,0.08)',border:'1px solid rgba(16,185,129,0.14)'}}>
                      <p className="text-gray-500 text-[10px] mb-0.5 flex items-center gap-1"><TrendingUp size={9} className="text-emerald-400"/>Uptime</p>
                      <p className="text-emerald-400 font-bold">{m.uptime_percentage}%</p>
                    </div>
                    {m.last_response_time_ms ? (
                      <div className="rounded-lg px-2.5 py-2" style={{background:'rgba(255,255,255,0.04)',border:'1px solid rgba(255,255,255,0.08)'}}>
                        <p className="text-gray-500 text-[10px] mb-0.5">Response</p>
                        <p className="text-white font-bold">{m.last_response_time_ms}ms</p>
                      </div>
                    ) : <div />}
                    <div className="rounded-lg px-2.5 py-2" style={{background:'rgba(255,255,255,0.04)',border:'1px solid rgba(255,255,255,0.08)'}}>
                      <p className="text-gray-500 text-[10px] mb-0.5 flex items-center gap-1"><TrendingDown size={9}/>Last check</p>
                      <p className="text-white font-bold text-xs">
                        {m.last_checked_at ? (() => { const d=Math.floor((Date.now()-new Date(m.last_checked_at))/1000); return d<60?`${d}s ago`:d<3600?`${Math.floor(d/60)}m ago`:`${Math.floor(d/3600)}h ago`; })() : 'Never'}
                      </p>
                    </div>
                  </div>
                  <div className="h-1.5 rounded-full overflow-hidden" style={{background:'rgba(255,255,255,0.06)'}}>
                    <div className="h-full rounded-full transition-all duration-700"
                      style={{width:`${m.uptime_percentage}%`,background:`linear-gradient(90deg,${ac}60,${ac})`,boxShadow:`0 0 6px ${ac}60`}} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Recent Incidents */}
        <div className="rounded-2xl overflow-hidden fu-3"
          style={{background:'linear-gradient(160deg,#0f1623,#111827)',border:'1px solid rgba(255,255,255,0.07)'}}>
          <div className="px-6 py-5 flex items-center justify-between"
            style={{borderBottom:'1px solid rgba(255,255,255,0.06)',background:'rgba(255,255,255,0.015)'}}>
            <div>
              <h2 className="text-white font-bold text-lg leading-none mb-1">Recent Incidents</h2>
              <p className="text-gray-500 text-xs">
                <span className="text-red-400 font-semibold">{openCount} open</span>
                <span className="mx-1.5 text-gray-700">·</span>
                <span className="text-emerald-400 font-semibold">{resolvedCount} resolved</span>
              </p>
            </div>
            <Link to="/user/incidents"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-white"
              style={{background:'linear-gradient(135deg,#b91c1c,#ef4444)',boxShadow:'0 0 16px #ef444440'}}>
              View All <ExternalLink size={11} />
            </Link>
          </div>

          <div className="p-4 space-y-2.5 max-h-[500px] overflow-y-auto slim">
            {incidents.length === 0 ? (
              <div className="py-16 text-center">
                <div className="w-14 h-14 rounded-2xl flex items-center justify-center mx-auto mb-4"
                  style={{background:'rgba(16,185,129,0.1)',border:'1px solid rgba(16,185,129,0.2)'}}>
                  <Zap size={24} className="text-emerald-400" />
                </div>
                <p className="text-white font-bold text-sm">All Clear! 🎉</p>
                <p className="text-gray-500 text-xs mt-1">No incidents recorded</p>
              </div>
            ) : incidents.slice(0, 10).map(inc => {
              const isOpen = inc.status === 'open';
              const borderColor = isOpen ? 'rgba(239,68,68,0.2)' : 'rgba(16,185,129,0.14)';
              const bgColor     = isOpen ? 'rgba(239,68,68,0.05)' : 'rgba(16,185,129,0.04)';
              const bgHover     = isOpen ? 'rgba(239,68,68,0.09)' : 'rgba(16,185,129,0.08)';
              const borderHover = isOpen ? 'rgba(239,68,68,0.4)' : 'rgba(16,185,129,0.3)';
              return (
                <div key={inc.id}
                  onClick={() => navigate(`/user/incidents?monitor=${inc.monitor_id}&highlight=${inc.id}`)}
                  className="irow relative rounded-xl p-4 cursor-pointer"
                  style={{background:bgColor, border:`1px solid ${borderColor}`}}
                  onMouseEnter={e=>{e.currentTarget.style.background=bgHover;e.currentTarget.style.borderColor=borderHover;}}
                  onMouseLeave={e=>{e.currentTarget.style.background=bgColor;e.currentTarget.style.borderColor=borderColor;}}
                >
                  {/* Left accent bar always red — OPEN origin */}
                  <div className="absolute left-0 top-3 bottom-3 w-0.5 rounded-r"
                    style={{background:'#ef4444', boxShadow:'0 0 6px #ef4444'}} />

                  <div className="flex items-start gap-3">
                    <div className="p-2 rounded-xl flex-shrink-0"
                      style={{background:'rgba(239,68,68,0.15)',border:'1px solid rgba(239,68,68,0.22)'}}>
                      <AlertCircle size={16} color="#ef4444"/>
                    </div>
                    <div className="flex-1 min-w-0">
                      <h3 className="text-white font-semibold text-sm truncate mb-2">{inc.monitor?.name}</h3>

                      {/* Status timeline: OPEN always shown, RESOLVED appended when done */}
                      <div className="flex flex-col gap-0 text-xs">

                        {/* OPEN — always visible */}
                        <div className="flex items-start gap-2">
                          <div className="flex flex-col items-center pt-0.5">
                            <span className="w-1.5 h-1.5 rounded-full bg-red-400 flex-shrink-0"
                              style={{boxShadow:'0 0 4px #f87171'}}/>
                            {!isOpen && <div className="w-px bg-gray-700 mt-0.5" style={{height:'16px'}}/>}
                          </div>
                          <div className="pb-1">
                            <span className="font-bold text-red-400">OPEN</span>
                            <p className="text-gray-500 flex items-center gap-1 mt-0.5">
                              <Clock size={9} className="text-gray-600"/>
                              {new Date(inc.started_at).toLocaleString()}
                            </p>
                          </div>
                        </div>

                        {/* RESOLVED — only appears once resolved */}
                        {!isOpen && (
                          <div className="flex items-start gap-2">
                            <div className="pt-0.5">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 flex-shrink-0 block"
                                style={{boxShadow:'0 0 4px #34d399'}}/>
                            </div>
                            <div>
                              <span className="font-bold text-emerald-400">RESOLVED</span>
                              {inc.resolved_at && (
                                <p className="text-gray-500 flex items-center gap-1 mt-0.5">
                                  <Activity size={9} className="text-gray-600"/>
                                  {new Date(inc.resolved_at).toLocaleString()}
                                </p>
                              )}
                            </div>
                          </div>
                        )}
                      </div>

                      {/* Duration */}
                      {inc.down_duration_seconds && (
                        <p className="text-amber-400 font-semibold flex items-center gap-1.5 mt-1.5 text-xs">
                          <Zap size={10}/>{Math.floor(inc.down_duration_seconds/60)}m {inc.down_duration_seconds%60}s downtime
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 fu-4">
        <StatsChart
          title="Monitors Added"
          data={monitorStats}
          color="#10b981"
          period={monitorPeriod}
          onPeriodChange={v => setPeriod('monitorPeriod', v)}
          unit="monitors"
        />
        <IncidentsByMonitorChart
          incidents={incidents}
          period={causePeriod}
          onPeriodChange={v => setPeriod('causePeriod', v)}
        />
        <StatsChart
          title="Incidents Over Time"
          data={incidentStats}
          color="#ef4444"
          period={incidentPeriod}
          onPeriodChange={v => setPeriod('incidentPeriod', v)}
          unit="incidents"
        />
      </div>
    </div>
  );
}