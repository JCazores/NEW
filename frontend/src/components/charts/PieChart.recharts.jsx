import { PieChart as RechartsPie, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

export default function PieChartRecharts({ chartData, total, CustomTooltip }) {
  return (
    <div>
      {/* Donut */}
      <div style={{ position: 'relative' }}>
        <ResponsiveContainer width="100%" height={240}>
          <RechartsPie>
            <Pie
              data={chartData}
              cx="50%"
              cy="50%"
              innerRadius={52}
              outerRadius={78}
              paddingAngle={3}
              dataKey="value"
              stroke="none"
            >
              {chartData.map((entry, i) => (
                <Cell
                  key={i}
                  fill={entry.color}
                  style={{ filter: `drop-shadow(0 0 7px ${entry.color}90)`, cursor: 'pointer' }}
                />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
          </RechartsPie>
        </ResponsiveContainer>

        {/* Center counter */}
        <div
          style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            textAlign: 'center',
            pointerEvents: 'none',
          }}
        >
          <p style={{ color: '#e2e8f0', fontSize: 26, fontWeight: 900, margin: 0, lineHeight: 1 }}>{total}</p>
          <p style={{ color: '#334155', fontSize: 9, marginTop: 2, letterSpacing: '0.1em' }}>TOTAL</p>
        </div>
      </div>

      {/* Legend with mini progress bars */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 7, marginTop: 4 }}>
        {chartData.map((entry) => (
          <div key={entry.key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div
                style={{
                  width: 7,
                  height: 7,
                  borderRadius: 2,
                  background: entry.color,
                  boxShadow: `0 0 6px ${entry.color}`,
                  flexShrink: 0,
                }}
              />
              <span style={{ color: '#94a3b8', fontSize: 11 }}>{entry.name}</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div
                style={{
                  width: 56,
                  height: 3,
                  borderRadius: 3,
                  background: 'rgba(255,255,255,0.07)',
                  overflow: 'hidden',
                }}
              >
                <div
                  style={{
                    width: `${(entry.value / total) * 100}%`,
                    height: '100%',
                    background: entry.color,
                    boxShadow: `0 0 4px ${entry.color}`,
                  }}
                />
              </div>
              <span
                style={{
                  color: '#e2e8f0',
                  fontSize: 12,
                  fontWeight: 700,
                  minWidth: 18,
                  textAlign: 'right',
                }}
              >
                {entry.value}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}