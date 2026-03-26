/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      keyframes: {
        pulse_green: {
          '0%, 100%': { boxShadow: '0 0 0 0 rgba(34,197,94,0.7)' },
          '70%': { boxShadow: '0 0 0 10px rgba(34,197,94,0)' },
        },
        pulse_red: {
          '0%, 100%': { boxShadow: '0 0 0 0 rgba(239,68,68,0.7)' },
          '70%': { boxShadow: '0 0 0 10px rgba(239,68,68,0)' },
        },
        blink: {
          '0%, 100%': { opacity: 1 },
          '50%': { opacity: 0.3 },
        },
      },
      animation: {
        'ping-green': 'pulse_green 1.5s ease-in-out infinite',
        'ping-red': 'pulse_red 1.5s ease-in-out infinite',
        'blink': 'blink 1s ease-in-out infinite',
      },
    },
  },
  plugins: [],
}