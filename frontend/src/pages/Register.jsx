import { useState } from "react";
import { Link, Navigate, useNavigate } from "react-router-dom";
import { api } from "../api.js";
import { useAuth } from "../AuthContext.jsx";

export default function Register() {
  const { token, setSession } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({
    full_name: "",
    email: "",
    password: "",
    confirm_password: "",
  });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  if (token) return <Navigate to="/" replace />;

  async function onSubmit(e) {
    e.preventDefault();
    setError("");

    // Validate password match
    if (form.password !== form.confirm_password) {
      setError("Passwords do not match. Please verify both password fields.");
      return;
    }

    if (form.password.length < 8) {
      setError("Password must be at least 8 characters long.");
      return;
    }

    setBusy(true);
    try {
      const data = await api.register(form);
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
          <p className="eyebrow">PhishGuard Security</p>
        </div>
        <h1>Secure Workspace Registration</h1>
        <p>
          Create your private threat detection console with JWT authentication,
          real-time threat intelligence, and persistent scan audit logs.
        </p>
        <div className="security-notice" style={{ marginTop: "20px", fontSize: "0.85rem", color: "var(--muted)" }}>
          <p>🔒 <strong>Account Security Policies:</strong></p>
          <ul style={{ paddingLeft: "20px", margin: "6px 0" }}>
            <li>Must be a legitimate, non-disposable email (e.g. Gmail, Outlook, organizational domain).</li>
            <li>Duplicate registrations are prevented; existing accounts must sign in using the login page.</li>
          </ul>
        </div>
      </div>

      <form className="card auth-card" onSubmit={onSubmit}>
        <h2>Create Account</h2>

        <label>
          Full name
          <input
            required
            minLength={2}
            placeholder="John Doe"
            value={form.full_name}
            onChange={(e) => setForm({ ...form, full_name: e.target.value })}
          />
        </label>

        <label>
          Genuine Email Address
          <input
            type="email"
            required
            placeholder="name@company.com or name@gmail.com"
            value={form.email}
            onChange={(e) => setForm({ ...form, email: e.target.value })}
          />
          <span style={{ fontSize: "0.75rem", color: "var(--muted)" }}>
            Disposable and dummy email providers are blocked.
          </span>
        </label>

        <label>
          Password (min 8 characters)
          <input
            type="password"
            required
            minLength={8}
            placeholder="••••••••••••"
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
          />
        </label>

        <label>
          Confirm Password
          <input
            type="password"
            required
            minLength={8}
            placeholder="••••••••••••"
            value={form.confirm_password}
            onChange={(e) => setForm({ ...form, confirm_password: e.target.value })}
          />
        </label>

        {error && <div className="error-alert">⚠️ {error}</div>}

        <button type="submit" disabled={busy}>
          {busy ? "Validating & Creating…" : "Create Account"}
        </button>

        <p className="muted" style={{ textAlign: "center", marginTop: "10px" }}>
          Already have an account? <Link to="/login">Sign in here</Link>
        </p>
      </form>
    </div>
  );
}
