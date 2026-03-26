export default function Logo({ size = 'default' }) {
  const sizes = {
    small: 'h-6',
    default: 'h-10',
    large: 'h-14',
  };

  return (
    <img
      src="/logo.png"
      alt="ServerSentinel"
      className={`${sizes[size]} w-auto object-contain`}
    />
  );
}