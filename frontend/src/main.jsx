import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles/globals.css";
import { loadPreferences } from "./services/preferences";

document.documentElement.classList.toggle("density-compact", loadPreferences().density === "compact");

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
