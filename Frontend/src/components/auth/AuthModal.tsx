import React, { useState } from 'react';
import { 
  X, 
  Lock, 
  Mail, 
  User, 
  ShieldCheck, 
  ArrowRight, 
  KeyRound,
  CheckCircle2,
  AlertCircle
} from 'lucide-react';
import { GithubIcon } from '../common/Icons';
import { UserProfile, WorkspaceOrg } from '../../types/security';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAuthSuccess: (user: UserProfile, org: WorkspaceOrg) => void;
  onShowToast: (title: string, message?: string, type?: 'success' | 'info' | 'error') => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({
  isOpen,
  onClose,
  onAuthSuccess,
  onShowToast
}) => {
  if (!isOpen) return null;

  const [mode, setMode] = useState<'login' | 'register' | 'forgot'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setLoading(true);

    try {
      if (mode === 'login') {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Authentication failed');

        onAuthSuccess(
          {
            id: data.user.id,
            email: data.user.email,
            full_name: data.user.full_name,
            is_active: true,
            is_verified: data.user.is_verified,
            role: data.active_organization?.role || 'OWNER'
          },
          {
            id: data.active_organization?.id || 'demo-org',
            name: data.active_organization?.name || 'My Workspace',
            slug: data.active_organization?.slug || 'workspace',
            role: data.active_organization?.role || 'OWNER'
          }
        );
        onShowToast("Authentication Successful", `Welcome back, ${data.user.full_name}`, "success");
        onClose();
      } else if (mode === 'register') {
        if (password !== confirmPassword) {
          throw new Error("Passwords do not match");
        }
        const res = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            full_name: fullName,
            email,
            password,
            confirm_password: confirmPassword
          })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Registration failed');

        onAuthSuccess(
          {
            id: data.user.id,
            email: data.user.email,
            full_name: data.user.full_name,
            is_active: true,
            is_verified: data.user.is_verified,
            role: 'OWNER'
          },
          {
            id: data.active_organization?.id || 'new-org',
            name: data.active_organization?.name || `${fullName}'s Workspace`,
            slug: data.active_organization?.slug || 'personal',
            role: 'OWNER'
          }
        );
        onShowToast("Account Created", "Your personal security workspace has been initialized", "success");
        onClose();
      } else if (mode === 'forgot') {
        const res = await fetch('/api/auth/forgot-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email })
        });
        if (!res.ok) throw new Error("Could not process request");
        onShowToast("Password Reset Dispatched", "If this email exists, a reset link was generated.", "info");
        setMode('login');
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="w-full max-w-md bg-bg-secondary border border-border rounded-lg shadow-elevated overflow-hidden animate-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border bg-bg-elevated/40">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-accent-primary" />
            <span className="font-mono text-sm font-bold text-text-primary">
              ShipSafe Identity & Workspace
            </span>
          </div>
          <button
            onClick={onClose}
            className="text-text-muted hover:text-text-primary p-1 rounded hover:bg-bg-elevated transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-5">
          {errorMessage && (
            <div className="p-3 rounded bg-severity-critical/10 border border-severity-critical/30 text-severity-critical text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}

          <div className="flex border-b border-border text-xs font-mono">
            <button
              onClick={() => { setMode('login'); setErrorMessage(null); }}
              className={`pb-2.5 px-3 border-b-2 transition-colors ${
                mode === 'login'
                  ? 'border-accent-primary text-text-primary font-semibold'
                  : 'border-transparent text-text-muted hover:text-text-primary'
              }`}
            >
              Sign In
            </button>
            <button
              onClick={() => { setMode('register'); setErrorMessage(null); }}
              className={`pb-2.5 px-3 border-b-2 transition-colors ${
                mode === 'register'
                  ? 'border-accent-primary text-text-primary font-semibold'
                  : 'border-transparent text-text-muted hover:text-text-primary'
              }`}
            >
              Create Account
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4 text-xs font-mono">
            {mode === 'register' && (
              <div className="space-y-1.5">
                <label className="text-text-secondary flex items-center gap-1.5">
                  <User className="w-3.5 h-3.5 text-accent-secondary" />
                  <span>Full Name</span>
                </label>
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Alex Developer"
                  className="w-full bg-bg-main border border-border rounded px-3 py-2 text-text-primary focus:outline-none focus:border-accent-secondary"
                />
              </div>
            )}

            <div className="space-y-1.5">
              <label className="text-text-secondary flex items-center gap-1.5">
                <Mail className="w-3.5 h-3.5 text-accent-secondary" />
                <span>Work Email</span>
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="alex@acme.dev"
                className="w-full bg-bg-main border border-border rounded px-3 py-2 text-text-primary focus:outline-none focus:border-accent-secondary"
              />
            </div>

            {mode !== 'forgot' && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label className="text-text-secondary flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-accent-secondary" />
                    <span>Password</span>
                  </label>
                  {mode === 'login' && (
                    <button
                      type="button"
                      onClick={() => setMode('forgot')}
                      className="text-[10px] text-text-muted hover:text-accent-primary"
                    >
                      Forgot password?
                    </button>
                  )}
                </div>
                <input
                  type="password"
                  required
                  minLength={8}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full bg-bg-main border border-border rounded px-3 py-2 text-text-primary focus:outline-none focus:border-accent-secondary"
                />
              </div>
            )}

            {mode === 'register' && (
              <div className="space-y-1.5">
                <label className="text-text-secondary flex items-center gap-1.5">
                  <KeyRound className="w-3.5 h-3.5 text-accent-secondary" />
                  <span>Confirm Password</span>
                </label>
                <input
                  type="password"
                  required
                  minLength={8}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full bg-bg-main border border-border rounded px-3 py-2 text-text-primary focus:outline-none focus:border-accent-secondary"
                />
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded bg-accent-primary hover:bg-accent-primary-hover text-[#0B0F14] font-bold font-mono text-xs flex items-center justify-center gap-2 transition-colors disabled:opacity-50 mt-2"
            >
              <span>{loading ? 'Processing...' : (mode === 'login' ? 'Authenticate' : (mode === 'register' ? 'Register Workspace' : 'Send Reset Link'))}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>

          {/* GitHub OAuth Scaffolding */}
          <div className="pt-3 border-t border-border space-y-2">
            <button
              type="button"
              onClick={() => onShowToast("GitHub OAuth", "GitHub OAuth authorization endpoint configured in API.", "info")}
              className="w-full py-2 rounded bg-bg-elevated hover:bg-bg-hover border border-border text-xs font-mono text-text-primary flex items-center justify-center gap-2 transition-colors"
            >
              <GithubIcon className="w-4 h-4" />
              <span>Continue with GitHub</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
