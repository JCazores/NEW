import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Users, MonitorCheck, AlertCircle, Activity,
  ExternalLink, TrendingUp, TrendingDown, Shield,
  Zap, Clock, RefreshCw
} from 'lucide-react';
import StatusBadge from '../../components/shared/StatusBadge';
import StatsChart from '../../components/charts/StatsChart';
import PieChart from '../../components/charts/PieChart';
import BarChart from '../../components/charts/BarChart';
import api from '../../api/axios';
import { usePeriodStore } from '../../store/periodStore';

export default function AdminDashboard() {
  const [stats, setStats]                   = useState(null);
  const [monitors, setMonitors]             = useState([]);
  const [incidents, setIncidents]           = useState([]);
  const [incidentStats, setIncidentStats]   = useState([]);
  const [incidentsByCause, setIncidentsByCause] = useState([]);
  const [incidentsByUser, setIncidentsByUser]   = useState([]);
  const [loading, setLoading]               = useState(true);
  const [lastUpdated, setLastUpdated]       = useState(null);

  // ── monitor filter/sort (same as user dashboard) ──
  const [monitorFilter, setMonitorFilter]   = useState('all');
  const [monitorSort,   setMonitorSort]     = useState('default');

  const navigate = useNavigate();
  const { incidentPeriod, causePeriod, userPeriod, setPeriod } = usePeriodStore();

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => { fetchIncidentStats(); },    [incidentPeriod]);
  useEffect(() => { fetchIncidentsByCause(); }, [causePeriod]);
  useEffect(() => { fetchIncidentsByUser(); },  [userPeriod]);

  const fetchAll = async () => {
    try {
      const [dashRes, monRes, incRes] = await Promise.all([
        api.get('/admin/dashboard'),
        api.get('/admin/monitors?per_page=100'),
        api.get('/admin/incidents?per_page=10'),
      ]);
      setStats(dashRes.data.data);
      setMonitors(monRes.data.data || []);
      setIncidents(incRes.data.data || []);
      setLastUpdated(new Date());
    } catch (err) { console.error(err); }
    finally { setLoading(false); }
  };

  const fetchIncidentStats    = async () => { try { const r = await api.get(`/admin/incident-stats?period=${incidentPeriod}`);    setIncidentStats(r.data.data || []);    } catch {} };
  const fetchIncidentsByCause = async () => { try { const r = await api.get(`/admin/incidents-by-cause?period=${causePeriod}`);  setIncidentsByCause(r.data.data || []); } catch {} };
  const fetchIncidentsByUser  = async () => { try { const r = await api.get(`/admin/incidents-by-user?period=${userPeriod}`);    setIncidentsByUser(r.data.data || []);  } catch {} };

  const openCount     = incidents.filter(i => i.status === 'open').length;
  const resolvedCount = incidents.filter(i => i.status === 'resolved').length;

  // ── filtered + sorted monitors for the card ──
  const activeMonitors = monitors.filter(m => m.is_active !== false);
  const monitorsForCard = (monitorFilter === 'all' ? monitors : activeMonitors)
    .slice()
    .sort((a, b) => {
      if (monitorSort === 'default') return 0;
      const rank = (s, upFirst) => { const v = (s||'').toLowerCase(); return upFirst ? (v==='up'?0:1) : (v==='down'?0:1); };
      const ra = rank(a.last_status, monitorSort === 'asc');
      const rb = rank(b.last_status, monitorSort === 'asc');
      return ra !== rb ? ra - rb : (a.name||'').localeCompare(b.name||'');
    });

  const statCards = [
    { label:'Total Users',    value:stats?.total_users||0,    icon:Users,        color:'#3b82f6', link:'/admin/users',               sub:`${stats?.active_users||0} active` },
    { label:'Total Monitors', value:stats?.total_monitors||0, icon:MonitorCheck, color:'#10b981', link:'/admin/monitors?status=all',  sub:`${stats?.active_monitors||0} active` },
    { label:'Monitors Up',    value:stats?.monitors_up||0,    icon:Activity,     color:'#10b981', link:'/admin/monitors?status=up',   sub:`${Math.round(((stats?.monitors_up||0)/(stats?.total_monitors||1))*100)}% uptime` },
    { label:'Monitors Down',  value:stats?.monitors_down||0,  icon:AlertCircle,  color:(stats?.monitors_down||0)>0?'#ef4444':'#10b981', link:'/admin/monitors?status=down', sub:`${stats?.open_incidents||0} open incidents` },
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
        <p className="text-gray-600 text-xs mt-1">Loading system data</p>
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

      {/* ── Header ── */}
      <div className="flex items-start justify-between mb-10 fu-0">
        <div>
          <div className="flex items-center gap-2.5 mb-3">
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inset-0 rounded-full bg-emerald-400 opacity-50" />
              <span className="relative rounded-full h-2.5 w-2.5 bg-emerald-400 inline-flex" style={{boxShadow:'0 0 8px #10b981'}} />
            </span>
            <span className="text-emerald-400 text-xs font-bold tracking-[.2em] uppercase">Live Monitoring</span>
          </div>
          <h1 className="text-4xl font-black text-white tracking-tight leading-none">Admin Dashboard</h1>
          <p className="text-gray-500 text-sm mt-2">System-wide monitoring overview and analytics</p>
        </div>
        <div className="flex items-center gap-2 px-4 py-2 rounded-xl border border-gray-800 bg-gray-900">
          <RefreshCw size={12} className="text-emerald-400 animate-spin" style={{animationDuration:'3s'}} />
          <span className="text-gray-400 text-xs">
            {lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString()}` : 'Syncing...'}
          </span>
        </div>
      </div>

      {/* ── Stat Cards ── */}
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

      {/* ── Monitors + Incidents ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">

        {/* Recent Monitors — with filter + sort from user dashboard */}
        <div className="rounded-2xl overflow-hidden fu-2"
          style={{background:'linear-gradient(160deg,#0f1623,#111827)',border:'1px solid rgba(255,255,255,0.07)'}}>
          <div className="px-6 py-5 flex items-center justify-between"
            style={{borderBottom:'1px solid rgba(255,255,255,0.06)',background:'rgba(255,255,255,0.015)'}}>
            <div>
              <h2 className="text-white font-bold text-lg leading-none mb-1">Recent Monitors</h2>
              <p className="text-gray-500 text-xs">
                {monitorFilter === 'all' ? monitors.length : activeMonitors.length}{' '}
                {monitorFilter === 'all' ? 'total' : 'active'} monitors
              </p>
            </div>
            <div className="flex items-center gap-2">
              {/* Filter: Active / All */}
              <select value={monitorFilter} onChange={e => setMonitorFilter(e.target.value)}
                className="px-2.5 py-1.5 text-xs text-gray-300 rounded-lg outline-none cursor-pointer"
                style={{background:'#1a2232',border:'1px solid rgba(255,255,255,0.1)'}}>
                <option value="all">All</option>
                <option value="active">Active</option>
              </select>
              {/* Sort: Up first / Down first */}
              <select value={monitorSort} onChange={e => setMonitorSort(e.target.value)}
                className="px-2.5 py-1.5 text-xs text-gray-300 rounded-lg outline-none cursor-pointer"
                style={{background:'#1a2232',border:'1px solid rgba(255,255,255,0.1)'}}>
                <option value="default">Sort</option>
                <option value="asc">Up first</option>
                <option value="desc">Down first</option>
              </select>
              <Link to="/admin/monitors"
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
                <p className="text-gray-300 font-semibold text-sm">No monitors found</p>
              </div>
            ) : monitorsForCard.map(m => {
              const isUp = m.last_status === 'up';
              const ac   = isUp ? '#10b981' : '#ef4444';
              return (
                <div key={m.id}
                  onClick={() => {
                    const sortOrder = m.last_status === 'up' ? 'up_only' : 'down_only';
                    navigate(`/admin/monitors?highlight=${m.id}&sortOrder=${sortOrder}&resetFilters=1`);
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
                        <div className="flex items-center gap-3 mt-1.5 text-xs">
                          {m.user?.name && <span className="text-gray-600 flex items-center gap-1"><Users size={9}/>{m.user.name}</span>}
                          {m.url?.startsWith('https://') && m.ssl_days_remaining != null && (
                            <span className={`flex items-center gap-1 ${m.ssl_days_remaining<=7?'text-red-400':m.ssl_days_remaining<=30?'text-yellow-400':'text-emerald-400'}`}>
                              <Shield size={9}/> SSL {m.ssl_days_remaining}d
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                    <Link to={`/admin/incidents?monitor=${m.id}`} onClick={e=>e.stopPropagation()}
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

        {/* Recent Incidents — with status timeline */}
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
            <Link to="/admin/incidents"
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
              const isOpen      = inc.status === 'open';
              const borderColor = isOpen ? 'rgba(239,68,68,0.2)' : 'rgba(16,185,129,0.14)';
              const bgColor     = isOpen ? 'rgba(239,68,68,0.05)' : 'rgba(16,185,129,0.04)';
              const bgHover     = isOpen ? 'rgba(239,68,68,0.09)' : 'rgba(16,185,129,0.08)';
              const borderHover = isOpen ? 'rgba(239,68,68,0.4)' : 'rgba(16,185,129,0.3)';
              return (
                <div key={inc.id}
                  onClick={() => navigate(`/admin/incidents?monitor=${inc.monitor_id}&highlight=${inc.id}`)}
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
                      <h3 className="text-white font-semibold text-sm truncate mb-1">{inc.monitor?.name}</h3>
                      {inc.monitor?.user?.name && (
                        <p className="text-gray-600 text-xs mb-2 flex items-center gap-1">
                          <Users size={9}/>{inc.monitor.user.name}
                        </p>
                      )}

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

      {/* ── Charts ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 fu-4">
        <PieChart
          title="Incidents by Cause"
          data={incidentsByCause}
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
        <BarChart
          title="Incidents by User"
          data={incidentsByUser}
          period={userPeriod}
          onPeriodChange={v => setPeriod('userPeriod', v)}
        />
      </div>
    </div>
  );
}