/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Light theme warm neutral palette
        surface: {
          900: '#faf8f5',
          800: '#ffffff',
          700: '#f3efe8',
          600: '#e7e0d6',
        },
        // Rich Brown primary theme
        brown: {
          900: '#451a03',
          800: '#78350f',
          700: '#92400e',
          600: '#b45309',
          100: '#fef3c7',
          50:  '#fffbeb',
        },
        // Vibrant flat severity palette
        severity: {
          critical: '#dc2626',
          high:     '#d97706',
          medium:   '#ca8a04',
          low:      '#059669',
          info:     '#2563eb',
        },
        accent: '#78350f',
        'accent-light': '#92400e',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
    },
  },
  plugins: [],
}
