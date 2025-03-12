import React from "react";
import ReactDOM from "react-dom/client"; // ✅ ใช้ createRoot() จาก React 18+
import "./index.css";
import App from "./App";

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(
    <React.StrictMode>
        <App />
    </React.StrictMode>
);
