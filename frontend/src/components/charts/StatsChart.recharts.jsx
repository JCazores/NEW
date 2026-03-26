import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer,
} from 'recharts';

export default function StatsChartRecharts({
  data,
  color,
  gId,
  unit,
  CustomTooltip,
  CustomActiveDot,
}) {
  return (
    <ResponsiveContainer width="100%" height={280}>
      <AreaChart data={data} margin={{ top: 8, right: 4, left: -24, bottom: 0 }}>
        <defs>
          <linearGradient id={gId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"   stopColor={color} stopOpacity={0.35} />
            <stop offset="100%" stopColor={color} stopOpacity={0.01} />
          </linearGradient>
        </defs>

        <CartesianGrid stroke="rgba(255,255,255,0.06)" strokeDasharray="4 4" vertical={false} />
        <XAxis dataKey="date" tick={{ fill: '#475569', fontSize: 10 }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fill: '#475569', fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} />
        <Tooltip content={<CustomTooltip color={color} unit={unit} />} />

        <Area
          type="monotone"
          dataKey="count"
          stroke={color}
          strokeWidth={2.5}
          fill={`url(#${gId})`}
          dot={false}
          activeDot={<CustomActiveDot color={color} />}
          style={{ filter: `drop-shadow(0 0 8px ${color}70)` }}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}