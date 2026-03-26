import { Suspense, lazy, useMemo } from 'react';

const PieChartRecharts = lazy(() => import('./PieChart.recharts.jsx'));

const COLORS = {
  http_error: '#ef4444',
  timeout: '#f59e0b',
  connection: '#8b5cf6',
  dns: '#ec4899',
  ssl: '#06b6d4',
  unknown: '#64748b',
};

const ERROR_LABELS = {
  http_error: 'HTTP Error',
  timeout: 'Timeout',
  connection: 'Connection Failed',
  dns: 'DNS Failed',
  ssl: 'SSL Error',
  unknown: 'Unknown',
};

const PERIODS = [
  { value: 'hour', label: 'Hour' },
  { value: 'day', label: '24h' },
  { value: 'week', label: 'Week' },
  { value: 'month', label: 'Month' },
];

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  const item = payload[0];
  return (
    <div
      style={{
        background: 'rgba(13,18,30,0.97)',
        border: `1px solid ${item.payload.color}50`,
        borderRadius: 12,
        padding: '12px 16px',
        boxShadow: `0 8px 32px rgba(0,0,0,0.6), 0 0 20px ${item.payload.color}20`,
        backdropFilter: 'blur(16px)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <div
          style={{
            width: 8,
            height: 8,
            borderRadius: '50%',
            background: item.payload.color,
            boxShadow: `0 0 6px ${item.payload.color}`,
          }}
        />
        <p style={{ color: '#94a3b8', fontSize: 11 }}>{item.name}</p>
      </div>
      <p style={{ color: item.payload.color, fontWeight: 800, fontSize: 22, lineHeight: 1 }}>{item.value}</p>
      <p style={{ color: '#334155', fontSize: 10, marginTop: 4 }}>incidents</p>
    </div>
  );
};

function Skeleton() {
  return (
    <div style={{ height: 320, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div
        style={{
          width: 64,
          height: 64,
          borderRadius: '50%',
          border: '2px solid rgba(255,255,255,0.07)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <div style={{ width: 28, height: 28, borderRadius: '50%', border: '2px solid rgba(255,255,255,0.07)' }} />
      </div>
    </div>
  );
}

export default function PieChart({ title, data, period, onPeriodChange }) {
  // Accept both raw API format and pre-mapped format
  const chartData = useMemo(() => {
    return (data || [])
      .map((item) => {
        // pre-mapped (already has .name, .value)
        if (item.name && item.value !== undefined) {
          return {
            name: item.name,
            value: item.value,
            color: COLORS[item.key] || COLORS[item.error_type] || '#64748b',
            key: item.key || item.error_type || item.name,
          };
        }
        // raw API format
        return {
          name: ERROR_LABELS[item.error_type] || item.error_type || 'Unknown',
          value: item.count,
          color: COLORS[item.error_type] || COLORS.unknown,
          key: item.error_type,
        };
      })
      .filter((d) => d.value > 0);
  }, [data]);

  const total = useMemo(() => chartData.reduce((s, i) => s + i.value, 0), [chartData]);

  return (
    <div
      style={{
        background: 'linear-gradient(160deg, #0f1623 0%, #111827 100%)',
        border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: 20,
        padding: '22px 22px 16px',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Ambient glow */}
      <div
        style={{
          position: 'absolute',
          top: -30,
          right: -30,
          width: 140,
          height: 140,
          background: 'radial-gradient(circle, #ef444418 0%, transparent 70%)',
          pointerEvents: 'none',
        }}
      />

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
        <div>
          <p
            style={{
              color: '#334155',
              fontSize: 10,
              textTransform: 'uppercase',
              letterSpacing: '0.12em',
              marginBottom: 4,
            }}
          >
            ROOT CAUSE
          </p>
          <h3 style={{ color: '#e2e8f0', fontSize: 15, fontWeight: 700, margin: 0 }}>{title}</h3>
        </div>

        <div
          style={{
            display: 'flex',
            gap: 2,
            background: 'rgba(255,255,255,0.05)',
            border: '1px solid rgba(255,255,255,0.08)',
            borderRadius: 10,
            padding: 3,
          }}
        >
          {PERIODS.map((p) => (
            <button
              key={p.value}
              onClick={() => onPeriodChange(p.value)}
              style={{
                padding: '4px 10px',
                borderRadius: 7,
                border: 'none',
                cursor: 'pointer',
                fontSize: 11,
                fontWeight: 700,
                transition: 'all .2s',
                background: period === p.value ? '#ef4444' : 'transparent',
                color: period === p.value ? '#fff' : '#4b5563',
                boxShadow: period === p.value ? '0 0 14px #ef444470' : 'none',
              }}
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {chartData.length > 0 ? (
        <Suspense fallback={<Skeleton />}>
          <PieChartRecharts chartData={chartData} total={total} CustomTooltip={CustomTooltip} />
        </Suspense>
      ) : (
        <div
          style={{
            height: 320,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 10,
          }}
        >
          <div
            style={{
              width: 64,
              height: 64,
              borderRadius: '50%',
              border: '2px solid rgba(255,255,255,0.07)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <div style={{ width: 28, height: 28, borderRadius: '50%', border: '2px solid rgba(255,255,255,0.07)' }} />
          </div>
          <p style={{ color: '#1e293b', fontSize: 13, fontWeight: 500 }}>No incident data for this period</p>
        </div>
      )}
    </div>
  );
}