const config = {
  up: {
    label: 'UP',
    bg: 'bg-green-500/20',
    text: 'text-green-400',
    dot: 'bg-green-400',
    animation: 'animate-ping-green',
  },
  down: {
    label: 'DOWN',
    bg: 'bg-red-500/20',
    text: 'text-red-400',
    dot: 'bg-red-400',
    animation: 'animate-blink',
  },
  unknown: {
    label: 'CHECKING',
    bg: 'bg-yellow-500/20',
    text: 'text-yellow-400',
    dot: 'bg-yellow-400',
    animation: 'animate-pulse',
  },
};

export default function StatusBadge({ status }) {
  const s = status?.toLowerCase() || 'unknown';
  const c = config[s] || config.unknown;

  return (
    <span
      // key helps React re-render when status changes (for transition)
      key={s}
      className={[
        'inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-bold',
        'transition-all duration-200 ease-out',
        'scale-100 opacity-100',
        c.bg,
        c.text,
      ].join(' ')}
    >
      <span className="relative flex h-2.5 w-2.5">
        <span
          className={[
            'absolute inline-flex h-full w-full rounded-full opacity-75',
            c.dot,
            c.animation,
          ].join(' ')}
        />
        <span className={['relative inline-flex rounded-full h-2.5 w-2.5', c.dot].join(' ')} />
      </span>

      {c.label}
    </span>
  );
}