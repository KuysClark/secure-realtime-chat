import daisyui from "daisyui";

/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx}",
  ],
  plugins: [daisyui],
  daisyui: {
    themes: ["light", "dark"],
  },
};
