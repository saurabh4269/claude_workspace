/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        display: ['DM Sans', 'sans-serif'],
      },
      colors: {
        brand: {
          green: '#93cb52',
          teal: '#1c9770',
          'light-teal': '#bef3e2',
          'light-red': '#f2eeee',
          gray: '#464646',
        },
        risk: {
          low: '#93cb52',
          medium: '#f59e0b',
          high: '#f97316',
          critical: '#dc2626',
        },
      },
    },
  },
  plugins: [],
}
