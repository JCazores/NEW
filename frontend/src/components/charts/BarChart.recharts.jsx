import {
  BarChart as RechartsBar,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';

const RoundBar = ({ x, y, width, height, color }) => {
  if (!height || height <= 0) return null;
  const r = Math.min(5, width / 2);
  const gId = `bg-${(color || '').replace('#', '')}`;
  return (
    <g>
      <defs>
        <linearGradient id={gId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity={0.95} />
          <stop offset="100%" stopColor={color} stopOpacity={0.2} />
        </linearGradient>
      </defs>
      <path
        d={`M${x + r},${y} H${x + width - r} Q${x + width},${y} ${x + width},${y + r} V${y + height} H${x} V${y + r} Q${x},${y} ${x + r},${y} Z`}
        fill={`url(#${gId})`}
        style={{ filter: `drop-shadow(0 0 6px ${color}60)` }}
      />
      <rect
        x={x + 1}
        y={y}
        width={width - 2}
        height={3}
        rx={r}
        fill={color}
        style={{ filter: `drop-shadow(0 0 4px ${color})` }}
      />
    </g>
  );
};

export default function BarChartRecharts({ coloredData, PALETTE, CustomTooltip, CustomXTick }) {
  return (
    <ResponsiveContainer width="100%" height={300}>
      <RechartsBar data={coloredData} margin={{ top: 10, right: 8, left: -20, bottom: 10 }}>
        <CartesianGrid stroke="rgba(255,255,255,0.05)" strokeDasharray="4 4" vertical={false} />
        <XAxis
          dataKey="user_name"
          tick={<CustomXTick />}
          axisLine={{ stroke: 'rgba(255,255,255,0.08)' }}
          tickLine={false}
          interval={0}
          height={40}
        />
        <YAxis tick={{ fill: '#475569', fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} />
        <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />

        <Bar
          dataKey="count"
          maxBarSize={48}
          shape={(props) => {
            // recharts passes props.payload with the row
            const name = props?.payload?.user_name;
            const idx = coloredData.findIndex((d) => d.user_name === name);
            return <RoundBar {...props} color={PALETTE[(idx >= 0 ? idx : 0) % PALETTE.length]} />;
          }}
        >
          {coloredData.map((_, i) => (
            <Cell key={i} fill={PALETTE[i % PALETTE.length]} />
          ))}
        </Bar>
      </RechartsBar>
    </ResponsiveContainer>
  );
}