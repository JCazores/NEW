import { Suspense, lazy, useMemo } from 'react';

const BarChartRecharts = lazy(() => import('./BarChart.recharts.jsx'));

const PERIODS = [
  { value: 'hour', label: 'Hour' },
  { value: 'day', label: '24h' },
  { value: 'week', label: 'Week' },
  { value: 'month', label: 'Month' },
];

const PALETTE = ['#3b82f6', '#10b981', '#8b5cf6', '#f59e0b', '#ef4444', '#06b6d4', '#ec4899'];

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  const color = payload[0]?.payload?._color || '#3b82f6';
  return (
    <div
      style={{
        background: 'rgba(13,18,30,0.97)',
        border: `1px solid ${color}50`,
        borderRadius: 12,
        padding: '12px 16px',
        boxShadow: `0 8px 32px rgba(0,0,0,0.6), 0 0 20px ${color}20`,
      }}
    >
      <p style={{ color: '#64748b', fontSize: 11, marginBottom: 6 }}>{label}</p>
      <p style={{ color, fontWeight: 800, fontSize: 22, lineHeight: 1 }}>{payload[0].value}</p>
      <p style={{ color: '#334155', fontSize: 10, marginTop: 4 }}>incidents</p>
    </div>
  );
};

// Upright label directly below axis — no rotation, clean
const CustomXTick = ({ x, y, payload }) => (
  <g transform={`translate(${x},${y})`}>
    <text x={0} y={0} dy={14} textAnchor="middle" fill="#475569" fontSize={11}>
      {payload.value?.length > 12 ? payload.value.slice(0, 12) + '…' : payload.value}
    </text>
  </g>
);

function Skeleton() {
  return (
    <div style={{ height: 300, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ display: 'flex', gap: 4, alignItems: 'flex-end', opacity: 0.2 }}>
        {[18, 30, 12, 24, 10, 20].map((h, i) => (
          <div
            key={i}
            style={{
              width: 8,
              height: h,
              background: PALETTE[i % PALETTE.length],
              borderRadius: '3px 3px 0 0',
            }}
          />
        ))}
      </div>
    </div>
  );
}

export default function BarChart({ title, data, period, onPeriodChange }) {
  const coloredData = useMemo(
    () =>
      (data || []).map((row, i) => ({
        ...row,
        _color: PALETTE[i % PALETTE.length],
      })),
    [data]
  );

  return (
    <div
      style={{
        background: 'linear-gradient(160deg, #0f1623 0%, #111827 100%)',
        border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: 20,
        padding: '22px 22px 20px',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      <div
        style={{
          position: 'absolute',
          bottom: -20,
          left: '50%',
          transform: 'translateX(-50%)',
          width: 200,
          height: 80,
          background: 'radial-gradient(ellipse, #3b82f615 0%, transparent 70%)',
          pointerEvents: 'none',
        }}
      />

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
        <div>
          <p style={{ color: '#334155', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 4 }}>
            BREAKDOWN
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
                background: period === p.value ? '#3b82f6' : 'transparent',
                color: period === p.value ? '#fff' : '#4b5563',
                boxShadow: period === p.value ? '0 0 14px #3b82f670' : 'none',
              }}
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {coloredData.length > 0 ? (
        <Suspense fallback={<Skeleton />}>
          <BarChartRecharts
            coloredData={coloredData}
            PALETTE={PALETTE}
            CustomTooltip={CustomTooltip}
            CustomXTick={CustomXTick}
          />
        </Suspense>
      ) : (
        <div
          style={{
            height: 300,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 10,
          }}
        >
          <div style={{ display: 'flex', gap: 4, alignItems: 'flex-end', opacity: 0.2 }}>
            {[18, 30, 12, 24, 10, 20].map((h, i) => (
              <div key={i} style={{ width: 8, height: h, background: PALETTE[i % PALETTE.length], borderRadius: '3px 3px 0 0' }} />
            ))}
          </div>
          <p style={{ color: '#1e293b', fontSize: 13, fontWeight: 500 }}>No data for this period</p>
        </div>
      )}
    </div>
  );
}