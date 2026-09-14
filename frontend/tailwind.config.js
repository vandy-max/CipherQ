/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        canvas: {
          DEFAULT: "#f4f5f8",
          soft: "#eceef3",
          panel: "#fbfbfd",
        },
        ink: {
          DEFAULT: "#0f1420",
          900: "#0b0f19",
          800: "#131a2b",
          700: "#1b2338",
        },
        brand: {
          50: "#eef1ff",
          100: "#e0e4ff",
          200: "#c3caff",
          300: "#9ba5ff",
          400: "#6f79f5",
          500: "#4d55e0",
          600: "#3a3fc4",
          700: "#2f339e",
          800: "#242774",
          900: "#161a4d",
        },
        quantum: {
          DEFAULT: "#7c5cff",
          soft: "#efeaff",
        },
        mint: { DEFAULT: "#0ea678", soft: "#e3f8ef" },
        peach: { DEFAULT: "#e8672a", soft: "#fdece0" },
        rose: { DEFAULT: "#e0234f", soft: "#fde8ee" },
        sky: { DEFAULT: "#0f8fd6", soft: "#e5f4fc" },
        amber: { DEFAULT: "#b9760b", soft: "#fbf0dc" },

        // ---------------------------------------------------------------
        // CipherQ design tokens (from Stitch export, cipherq/DESIGN.md).
        // Namespaced under `cq-*` so they layer in without touching any
        // existing `canvas`/`ink`/`brand`/etc. usage. Pages are migrated
        // to these one at a time in later modules; nothing consumes them
        // yet in this module.
        // ---------------------------------------------------------------
        "cq-surface": "#11131c",
        "cq-surface-dim": "#11131c",
        "cq-surface-bright": "#373943",
        "cq-surface-container-lowest": "#0c0e17",
        "cq-surface-container-low": "#191b24",
        "cq-surface-container": "#1d1f29",
        "cq-surface-container-high": "#282933",
        "cq-surface-container-highest": "#33343e",
        "cq-on-surface": "#e2e1ef",
        "cq-on-surface-variant": "#c4c5d9",
        "cq-inverse-surface": "#e2e1ef",
        "cq-inverse-on-surface": "#2e303a",
        "cq-outline": "#8e90a2",
        "cq-outline-variant": "#434656",
        "cq-primary": "#b8c3ff",
        "cq-on-primary": "#002388",
        "cq-primary-container": "#2e5bff",
        "cq-on-primary-container": "#efefff",
        "cq-secondary": "#e6feff",
        "cq-on-secondary": "#003739",
        "cq-secondary-container": "#00f4fe",
        "cq-on-secondary-container": "#006c71",
        "cq-tertiary": "#e9b3ff",
        "cq-on-tertiary": "#510074",
        "cq-tertiary-container": "#a03ad3",
        "cq-on-tertiary-container": "#fdeaff",
        "cq-error": "#ffb4ab",
        "cq-on-error": "#690005",
        "cq-error-container": "#93000a",
        "cq-on-error-container": "#ffdad6",
        "cq-background": "#11131c",
        "cq-on-background": "#e2e1ef",
        "cq-surface-variant": "#33343e",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        display: ["'IBM Plex Sans'", "Inter", "system-ui", "sans-serif"],
        mono: ["'JetBrains Mono'", "monospace"],
      },
      fontSize: {
        // CipherQ type scale (DESIGN.md); coexists with Tailwind defaults.
        "cq-display-lg": ["48px", { lineHeight: "56px", letterSpacing: "-0.02em", fontWeight: "700" }],
        "cq-headline-lg": ["32px", { lineHeight: "40px", letterSpacing: "-0.01em", fontWeight: "600" }],
        "cq-headline-md": ["24px", { lineHeight: "32px", fontWeight: "600" }],
        "cq-body-lg": ["16px", { lineHeight: "24px", fontWeight: "400" }],
        "cq-body-md": ["14px", { lineHeight: "20px", fontWeight: "400" }],
        "cq-label-md": ["12px", { lineHeight: "16px", letterSpacing: "0.05em", fontWeight: "500" }],
        "cq-mono-sm": ["13px", { lineHeight: "18px", fontWeight: "400" }],
      },
      spacing: {
        "cq-unit": "4px",
        "cq-stack-sm": "8px",
        "cq-stack-md": "16px",
        "cq-stack-lg": "32px",
        "cq-gutter": "24px",
        "cq-margin-mobile": "16px",
        "cq-margin-desktop": "40px",
      },
      borderRadius: {
        xl2: "1.25rem",
        "cq-sm": "0.25rem",
        cq: "0.5rem",
        "cq-md": "0.75rem",
        "cq-lg": "1rem",
        "cq-xl": "1.5rem",
      },
      boxShadow: {
        card: "0 1px 2px rgba(15,20,32,0.04), 0 8px 24px -12px rgba(15,20,32,0.10)",
        "card-lg": "0 4px 12px rgba(15,20,32,0.06), 0 24px 48px -20px rgba(15,20,32,0.16)",
        glow: "0 0 0 1px rgba(77,85,224,0.12), 0 8px 24px -8px rgba(77,85,224,0.28)",
        "cq-glow-primary": "0 0 15px rgba(184,195,255,0.15)",
        "cq-glow-secondary": "0 0 15px rgba(99,247,255,0.15)",
        "cq-glow-tertiary": "0 0 15px rgba(233,179,255,0.15)",
        "cq-dot-secondary": "0 0 8px #63f7ff",
        "cq-dot-primary": "0 0 8px #b8c3ff",
        "cq-dot-error": "0 0 8px #ffb4ab",
        "cq-popover": "0 20px 60px -20px rgba(0,0,0,0.55), 0 0 0 1px rgba(184,195,255,0.08)",
      },
      backgroundImage: {
        "cq-matte": "radial-gradient(ellipse 80% 60% at 15% -10%, rgba(46,91,255,0.12), transparent 60%), radial-gradient(ellipse 60% 50% at 100% 0%, rgba(0,244,254,0.06), transparent 60%)",
      },
      keyframes: {
        shimmer: {
          "0%": { backgroundPosition: "-400px 0" },
          "100%": { backgroundPosition: "400px 0" },
        },
      },
      animation: {
        shimmer: "shimmer 1.6s linear infinite",
      },
    },
  },
  plugins: [],
};
