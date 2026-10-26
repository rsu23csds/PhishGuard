import { useState } from "react";
import { Link, Navigate, useNavigate } from "react-router-dom";
import { api } from "../api.js";
import { useAuth } from "../AuthContext.jsx";

export default function Login() {
  const { token, setSession } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ email: "", password: "" });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  if (token) return <Navigate to="/" replace />;

  async function onSubmit(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const data = await api.login(form);
      setSession(data.access_token);
      navigate("/");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-layout">
      <div className="auth-hero">
        <div className="auth-brand-wrap">
          <img src="/logo.png" alt="PhishGuard Mascot" className="auth-mascot" />
          <p className="eyebrow">PhishGuard Defense</p>
        </div>
        <h1>Stop phishing before credentials leave the inbox.</h1>
        <p>
          Dual-engine cybersecurity intelligence combining a 33-feature Random Forest ML model with real-time VirusTotal and Google Safe Browsing threat feeds.
        </p>
      </div>
      <form className="card auth-card" onSubmit={onSubmit}>
        <h2>Sign in</h2>
        <label>
          Email
          <input
            type="email"
            required
            value={form.email}
            onChange={(e) => setForm({ ...form, email: e.target.value })}
          />
        </label>
        <label>
          Password
          <input
            type="password"
            required
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
          />
        </label>
        {error && <p className="error">{error}</p>}
        <button type="submit" disabled={busy}>
          {busy ? "Signing in…" : "Enter dashboard"}
        </button>
        <p className="muted">
          New here? <Link to="/register">Create an account</Link>
        </p>
      </form>
    </div>
  );
}
