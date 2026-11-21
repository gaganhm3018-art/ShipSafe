/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bg: {
          main: '#0B0F14',
          sidebar: '#10161D',
          secondary: '#151D26',
          elevated: '#1B2632',
          hover: '#223040',
        },
        border: {
          subtle: '#22303E',
          DEFAULT: '#253444',
          active: '#3A4E66',
        },
        text: {
          primary: '#E8EDF3',
          secondary: '#98A6B5',
          muted: '#657384',
        },
        accent: {
          primary: '#45D6A0',
          'primary-hover': '#39BD8B',
          'primary-dim': 'rgba(69, 214, 160, 0.12)',
          secondary: '#65A8FF',
          'secondary-hover': '#4E93ED',
          'secondary-dim': 'rgba(101, 168, 255, 0.12)',
        },
        severity: {
          critical: '#F04452',
          'critical-bg': 'rgba(240, 68, 82, 0.12)',
          'critical-border': 'rgba(240, 68, 82, 0.35)',
          high: '#F28C45',
          'high-bg': 'rgba(242, 140, 69, 0.12)',
          'high-border': 'rgba(242, 140, 69, 0.35)',
          medium: '#E9BD55',
          'medium-bg': 'rgba(233, 189, 85, 0.12)',
          'medium-border': 'rgba(233, 189, 85, 0.35)',
          low: '#65A8FF',
          'low-bg': 'rgba(101, 168, 255, 0.12)',
          'low-border': 'rgba(101, 168, 255, 0.35)',
          info: '#8795A5',
          'info-bg': 'rgba(135, 149, 165, 0.12)',
          'info-border': 'rgba(135, 149, 165, 0.35)',
        }
      },
      fontFamily: {
        sans: ['Geist', 'Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Menlo', 'Monaco', 'Courier New', 'monospace'],
      },
      boxShadow: {
        'subtle': '0 1px 2px 0 rgba(0, 0, 0, 0.35)',
        'elevated': '0 4px 16px -2px rgba(0, 0, 0, 0.5), 0 2px 4px -2px rgba(0, 0, 0, 0.3)',
      }
    },
  },
  plugins: [],
}
