import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Lock, 
  Mail, 
  User, 
  ArrowRight, 
  CheckCircle2, 
  AlertCircle, 
  KeyRound, 
  Eye, 
  EyeOff, 
  Sparkles, 
  Building2, 
  ExternalLink,
  ShieldAlert,
  FileCode2,
  Cpu,
  Fingerprint
} from 'lucide-react';
import { GithubIcon } from '../common/Icons';
import { UserProfile, WorkspaceOrg } from '../../types/security';

interface AuthPageProps {
  onAuthSuccess: (user: UserProfile, org: WorkspaceOrg) => void;
  onShowToast: (title: string, message?: string, type?: 'success' | 'info' | 'error') => void;
  onExploreDemo?: () => void;
}

export const AuthPage: React.FC<AuthPageProps> = ({
  onAuthSuccess,
  onShowToast,
  onExploreDemo
}) => {
  const [mode, setMode] = useState<'login' | 'register' | 'forgot' | 'reset' | 'verify'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [orgName, setOrgName] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  const [rememberMe, setRememberMe] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Quick fill developer account
  const handleQuickFillDev = () => {
    setEmail('alex@acme.dev');
    setPassword('DevPassword123!');
    setErrorMessage(null);
  };

  // Password strength calculation
  const getPasswordStrength = (pass: string) => {
    if (!pass) return { score: 0, label: '', color: 'bg-border' };
    if (pass.length < 8) return { score: 1, label: 'Weak (min 8 chars)', color: 'bg-severity-critical' };
    
    let strength = 1;
    if (/[A-Z]/.test(pass)) strength++;
    if (/[0-9]/.test(pass)) strength++;
    if (/[^A-Za-z0-9]/.test(pass)) strength++;

    if (strength <= 2) return { score: 2, label: 'Fair', color: 'bg-severity-medium' };
    return { score: 3, label: 'Strong (RFC 9106)', color: 'bg-accent-primary' };
  };

  const strength = getPasswordStrength(password);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setSuccessMessage(null);
    setLoading(true);

    try {
      if (mode === 'login') {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: email.trim(), password })
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.detail || 'Invalid email or password');
        }

        const userObj: UserProfile = {
          id: data.user.id,
          email: data.user.email,
          full_name: data.user.full_name,
          is_active: true,
          is_verified: data.user.is_verified,
          role: data.active_organization?.role || 'OWNER',
          created_at: new Date().toISOString()
        };

        const orgObj: WorkspaceOrg = {
          id: data.active_organization?.id || 'org-core',
          name: data.active_organization?.name || 'Acme Production Core',
          slug: data.active_organization?.slug || 'acme-core',
          role: data.active_organization?.role || 'OWNER'
        };

        if (rememberMe) {
          localStorage.setItem('shipsafe_auth_user', JSON.stringify(userObj));
          localStorage.setItem('shipsafe_auth_org', JSON.stringify(orgObj));
          if (data.access_token) {
            localStorage.setItem('shipsafe_access_token', data.access_token);
          }
        }

        onAuthSuccess(userObj, orgObj);
        onShowToast('Welcome back', `Signed in as ${userObj.full_name}`, 'success');

      } else if (mode === 'register') {
        if (password !== confirmPassword) {
          throw new Error('Passwords do not match');
        }
        if (password.length < 8) {
          throw new Error('Password must be at least 8 characters long');
        }

        const res = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            full_name: fullName.trim(),
            email: email.trim(),
            password,
            confirm_password: confirmPassword,
            organization_name: orgName.trim() || undefined
          })
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.detail || 'Registration failed');
        }

        const userObj: UserProfile = {
          id: data.user.id,
          email: data.user.email,
          full_name: data.user.full_name,
          is_active: true,
          is_verified: data.user.is_verified,
          role: 'OWNER',
          created_at: new Date().toISOString()
        };

        const orgObj: WorkspaceOrg = {
          id: data.active_organization?.id || 'org-new',
          name: data.active_organization?.name || `${fullName}'s Workspace`,
          slug: data.active_organization?.slug || 'workspace',
          role: 'OWNER'
        };

        if (rememberMe) {
          localStorage.setItem('shipsafe_auth_user', JSON.stringify(userObj));
          localStorage.setItem('shipsafe_auth_org', JSON.stringify(orgObj));
          if (data.access_token) {
            localStorage.setItem('shipsafe_access_token', data.access_token);
          }
        }

        onAuthSuccess(userObj, orgObj);
        onShowToast('Account Provisioned', `Security workspace generated for ${userObj.email}`, 'success');

      } else if (mode === 'forgot') {
        const res = await fetch('/api/auth/forgot-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: email.trim() })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Could not process password recovery');

        setSuccessMessage('Recovery token dispatched. Check your inbox or proceed to token entry below.');
        setMode('reset');

      } else if (mode === 'reset') {
        const res = await fetch('/api/auth/reset-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            token: resetToken.trim(),
            new_password: newPassword,
            confirm_password: newPassword
          })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Password reset token invalid or expired');

        setSuccessMessage('Password successfully updated! You may now sign in.');
        setMode('login');
        setPassword('');

      } else if (mode === 'verify') {
        const res = await fetch('/api/auth/verify-email', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: verificationCode.trim() })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Verification code invalid');

        setSuccessMessage('Email verified successfully! You may now sign in.');
        setMode('login');
      }

    } catch (err: any) {
      setErrorMessage(err.message || 'Authentication request failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-bg-main text-text-primary flex flex-col justify-between selection:bg-accent-primary selection:text-black">
      {/* Top Banner */}
      <header className="border-b border-border/80 bg-bg-sidebar/90 backdrop-blur px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded bg-bg-elevated border border-border flex items-center justify-center text-accent-primary shadow-subtle">
            <ShieldCheck className="w-5 h-5 text-accent-primary" />
          </div>
          <div>
            <div className="font-mono font-bold text-base tracking-tight text-text-primary flex items-center gap-2">
              ShipSafe
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-accent-primary/10 text-accent-primary border border-accent-primary/20">
                v2.4
              </span>
            </div>
            <div className="text-[11px] font-mono text-text-muted">
              Developer-First Application Security Platform
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded bg-bg-secondary border border-border text-xs font-mono text-text-secondary">
            <span className="w-2 h-2 rounded-full bg-accent-primary animate-pulse" />
            <span>FastAPI Security Engine Online</span>
          </div>

          {onExploreDemo && (
            <button
              onClick={onExploreDemo}
              className="px-3 py-1.5 rounded bg-bg-elevated hover:bg-bg-hover border border-border text-xs font-mono text-text-primary hover:text-accent-primary transition-colors flex items-center gap-1.5"
            >
              <Sparkles className="w-3.5 h-3.5 text-accent-secondary" />
              <span>Explore Demo</span>
            </button>
          )}
        </div>
      </header>

      {/* Main Grid Content */}
      <main className="flex-1 flex items-center justify-center p-6 md:p-12">
        <div className="w-full max-w-5xl grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-center">
          
          {/* Left Column: Platform Security Showcase */}
          <div className="lg:col-span-6 space-y-6">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-accent-primary/10 border border-accent-primary/20 text-accent-primary text-xs font-mono font-medium">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Zero-Trust Enterprise SAST + DAST</span>
            </div>

            <div className="space-y-3">
              <h1 className="text-3xl md:text-4xl font-extrabold tracking-tight text-text-primary font-sans">
                Stop Vulnerabilities Before Merge
              </h1>
              <p className="text-sm md:text-base text-text-secondary leading-relaxed">
                Deterministic security analysis with Argon2id workspace authentication, GitHub repository inspection, passive perimeter audits, and automated AI remediation diffs.
              </p>
            </div>

            {/* Feature Highlights Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
              <div className="p-3.5 rounded bg-bg-secondary border border-border/80 hover:border-border-active transition-colors">
                <div className="flex items-center gap-2 text-accent-primary text-xs font-mono font-semibold mb-1">
                  <Fingerprint className="w-4 h-4" />
                  <span>Argon2id & RBAC</span>
                </div>
                <p className="text-xs text-text-muted leading-relaxed">
                  Strict tenant workspace isolation with role hierarchies (Owner, Admin, Dev, Viewer).
                </p>
              </div>

              <div className="p-3.5 rounded bg-bg-secondary border border-border/80 hover:border-border-active transition-colors">
                <div className="flex items-center gap-2 text-accent-secondary text-xs font-mono font-semibold mb-1">
                  <FileCode2 className="w-4 h-4" />
                  <span>Deterministic SAST</span>
                </div>
                <p className="text-xs text-text-muted leading-relaxed">
                  Zero hallucinations: catches SQLi, command execution, and hardcoded API tokens.
                </p>
              </div>

              <div className="p-3.5 rounded bg-bg-secondary border border-border/80 hover:border-border-active transition-colors">
                <div className="flex items-center gap-2 text-severity-high text-xs font-mono font-semibold mb-1">
                  <ShieldAlert className="w-4 h-4" />
                  <span>Passive DAST</span>
                </div>
                <p className="text-xs text-text-muted leading-relaxed">
                  Passive TLS, HSTS, CSP, and cookie auditing with strict SSRF defenses.
                </p>
              </div>

              <div className="p-3.5 rounded bg-bg-secondary border border-border/80 hover:border-border-active transition-colors">
                <div className="flex items-center gap-2 text-accent-primary text-xs font-mono font-semibold mb-1">
                  <Cpu className="w-4 h-4" />
                  <span>AI Remediation</span>
                </div>
                <p className="text-xs text-text-muted leading-relaxed">
                  Generates ready-to-merge unified git diffs with verified zero regressions.
                </p>
              </div>
            </div>

            {/* Developer credentials quick-fill trigger */}
            <div className="p-3 rounded bg-bg-elevated/70 border border-border flex items-center justify-between">
              <div className="text-xs font-mono text-text-muted">
                <span className="text-accent-secondary font-semibold">Test Account: </span>
                <span className="text-text-primary">alex@acme.dev</span> • 
                <span className="text-text-muted"> DevPassword123!</span>
              </div>
              <button
                type="button"
                onClick={handleQuickFillDev}
                className="px-2 py-1 rounded bg-accent-primary/10 hover:bg-accent-primary/20 text-accent-primary border border-accent-primary/30 text-[11px] font-mono font-medium transition-colors cursor-pointer"
              >
                Autofill
              </button>
            </div>
          </div>

          {/* Right Column: Interactive Authentication Box */}
          <div className="lg:col-span-6">
            <div className="bg-bg-secondary border border-border rounded-lg shadow-elevated overflow-hidden">
              {/* Tabs */}
              <div className="grid grid-cols-2 border-b border-border bg-bg-sidebar">
                <button
                  type="button"
                  onClick={() => {
                    setMode('login');
                    setErrorMessage(null);
                    setSuccessMessage(null);
                  }}
                  className={`py-3.5 text-xs font-mono font-semibold border-b-2 transition-colors flex items-center justify-center gap-2 ${
                    mode === 'login' || mode === 'forgot' || mode === 'reset'
                      ? 'border-accent-primary text-accent-primary bg-bg-secondary'
                      : 'border-transparent text-text-muted hover:text-text-primary'
                  }`}
                >
                  <Lock className="w-3.5 h-3.5" />
                  <span>Sign In</span>
                </button>

                <button
                  type="button"
                  onClick={() => {
                    setMode('register');
                    setErrorMessage(null);
                    setSuccessMessage(null);
                  }}
                  className={`py-3.5 text-xs font-mono font-semibold border-b-2 transition-colors flex items-center justify-center gap-2 ${
                    mode === 'register'
                      ? 'border-accent-primary text-accent-primary bg-bg-secondary'
                      : 'border-transparent text-text-muted hover:text-text-primary'
                  }`}
                >
                  <User className="w-3.5 h-3.5" />
                  <span>Create Account</span>
                </button>
              </div>

              {/* Form Body */}
              <div className="p-6 md:p-8 space-y-5">
                {errorMessage && (
                  <div className="p-3 rounded bg-severity-critical/10 border border-severity-critical/30 text-severity-critical text-xs flex items-center gap-2 animate-in fade-in">
                    <AlertCircle className="w-4 h-4 flex-shrink-0" />
                    <span>{errorMessage}</span>
                  </div>
                )}

                {successMessage && (
                  <div className="p-3 rounded bg-accent-primary/10 border border-accent-primary/30 text-accent-primary text-xs flex items-center gap-2 animate-in fade-in">
                    <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
                    <span>{successMessage}</span>
                  </div>
                )}

                <form onSubmit={handleSubmit} className="space-y-4">
                  
                  {/* SIGN IN VIEW */}
                  {mode === 'login' && (
                    <>
                      <div>
                        <label className="block text-xs font-mono font-medium text-text-secondary mb-1.5">
                          Username or Email Address
                        </label>
                        <div className="relative">
                          <Mail className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
                          <input
                            type="email"
                            required
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            placeholder="alex@acme.dev"
                            className="w-full pl-9 pr-3 py-2 bg-bg-elevated border border-border focus:border-accent-primary rounded text-xs font-mono text-text-primary placeholder:text-text-muted/60 focus:outline-none transition-colors"
                          />
                        </div>
                      </div>

                      <div>
                        <div className="flex items-center justify-between mb-1.5">
                          <label className="text-xs font-mono font-medium text-text-secondary">
                            Password
                          </label>
                          <button
                            type="button"
                            onClick={() => {
                              setMode('forgot');
                              setErrorMessage(null);
                            }}
                            className="text-[11px] font-mono text-accent-secondary hover:underline cursor-pointer"
                          >
                            Forgot password?
                          </button>
                        </div>
                        <div className="relative">
                          <Lock className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
                          <input
                            type={showPassword ? 'text' : 'password'}
                            required
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="••••••••••••"
                            className="w-full pl-9 pr-10 py-2 bg-bg-elevated border border-border focus:border-accent-primary rounded text-xs font-mono text-text-primary placeholder:text-text-muted/60 focus:outline-none transition-colors"
                          />
                          <button
                            type="button"
                            onClick={() => setShowPassword(!showPassword)}
                            className="text-text-muted hover:text-text-primary absolute right-3 top-1/2 -translate-y-1/2 cursor-pointer"
                          >
                            {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                          </button>
                        </div>
                      </div>

                      <div className="flex items-center justify-between text-xs font-mono">
                        <label className="flex items-center gap-2 cursor-pointer text-text-secondary select-none">
                          <input
                            type="checkbox"
                            checked={rememberMe}
                            onChange={(e) => setRememberMe(e.target.checked)}
                            className="rounded bg-bg-elevated border-border text-accent-primary focus:ring-0 focus:ring-offset-0"
                          />
                          <span>Remember session</span>
                        </label>
                      </div>

                      <button
                        type="submit"
                        disabled={loading}
                        className="w-full flex items-center justify-center gap-2 py-2.5 rounded bg-accent-primary hover:bg-accent-primary-hover text-[#0B0F14] text-xs font-mono font-bold transition-colors disabled:opacity-50 cursor-pointer shadow-subtle"
                      >
                        {loading ? (
                          <span className="inline-block w-4 h-4 border-2 border-black border-t-transparent rounded-full animate-spin" />
                        ) : (
                          <>
                            <span>Sign In to Workspace</span>
                            <ArrowRight className="w-4 h-4" />
                          </>
                        )}
                      </button>
                    </>
                  )}

                  {/* REGISTRATION VIEW */}
                  {mode === 'register' && (
                    <>
                      <div>
                        <label className="block text-xs font-mono font-medium text-text-secondary mb-1.5">
                          Full Name
                        </label>
                        <div className="relative">
                          <User className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
                          <input
                            type="text"
                            required
                            value={fullName}
                            onChange={(e) => setFullName(e.target.value)}
                            placeholder="Alex Developer"
                            className="w-full pl-9 pr-3 py-2 bg-bg-elevated border border-border focus:border-accent-primary rounded text-xs font-mono text-text-primary placeholder:text-text-muted/60 focus:outline-none transition-colors"
                          />
                        </div>
                      </div>

                      <div>
                        <label className="block text-xs font-mono font-medium text-text-secondary mb-1.5">
                          Work Email
                        </label>
                        <div className="relative">
                          <Mail className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
                          <input
                            type="email"
                            required
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            placeholder="alex@acme.dev"
                            className="w-full pl-9 pr-3 py-2 bg-bg-elevated border border-border focus:border-accent-primary rounded text-xs font-mono text-text-primary placeholder:text-text-muted/60 focus:outline-none transition-colors"
                          />
                        </div>
                      </div>

                      <div>
                        <label className="block text-xs font-mono font-medium text-text-secondary mb-1.5">
                          Initial Organization Name (Optional)
                        </label>
                        <div className="relative">
                          <Building2 className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
                          <input
                            type="text"
                            value={orgName}
                            onChange={(e) => setOrgName(e.target.value)}
                            placeholder="Acme Production Core"
                            className="w-full pl-9 pr-3 py-2 bg-bg-elevated border border-border focus:border-accent-primary rounded text-xs font-mono text-text-primary placeholder:text-text-muted/60 focus:outline-none transition-colors"
                          />
                        </div>
                      </div>

                      <div>
                        <label className="block text-xs font-mono font-medium text-text-secondary mb-1.5">
                          Password (Min 8 Characters)
                        </label>
                        <div className="relative">
                          <Lock className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
                          <input
                            type={showPassword ? 'text' : 'password'}
                            required
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="••••••••••••"
                            className="w-full pl-9 pr-10 py-2 bg-bg-elevated border border-border focus:border-accent-primary rounded text-xs font-mono text-text-primary placeholder:text-text-muted/60 focus:outline-none transition-colors"
                          />
                          <button
                            type="button"
                            onClick={() => setShowPassword(!showPassword)}
                            className="text-text-muted hover:text-text-primary absolute right-3 top-1/2 -translate-y-1/2 cursor-pointer"
                          >
                            {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                          </button>
                        </div>
                        {password && (
                          <div className="mt-1.5 flex items-center justify-between text-[11px] font-mono">
                            <span className="text-text-muted">Strength: {strength.label}</span>
                            <div className="flex gap-1">
                              <span className={`w-6 h-1 rounded ${strength.score >= 1 ? strength.color : 'bg-border'}`} />
                              <span className={`w-6 h-1 rounded ${strength.score >= 2 ? strength.color : 'bg-border'}`} />
                              <span className={`w-6 h-1 rounded ${strength.score >= 3 ? strength.color : 'bg-border'}`} />
                            </div>
                          </div>
                        )}
                      </div>

                      <div>
                        <label className="block text-xs font-mono font-medium text-text-secondary mb-1.5">
                          Confirm Password
                        </label>
                        <div className="relative">
                          <KeyRound className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
                          <input
                            type={showPassword ? 'text' : 'password'}
                            required
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            placeholder="••••••••••••"
                            className="w-full pl-9 pr-3 py-2 bg-bg-elevated border border-border focus:border-accent-primary rounded text-xs font-mono text-text-primary placeholder:text-text-muted/60 focus:outline-none transition-colors"
                          />
                        </div>
                      </div>

                      <button
                        type="submit"
                        disabled={loading}
                        className="w-full flex items-center justify-center gap-2 py-2.5 rounded bg-accent-primary hover:bg-accent-primary-hover text-[#0B0F14] text-xs font-mono font-bold transition-colors disabled:opacity-50 cursor-pointer shadow-subtle"
                      >
                        {loading ? (
                          <span className="inline-block w-4 h-4 border-2 border-black border-t-transparent rounded-full animate-spin" />
                        ) : (
                          <>
                            <span>Initialize Security Workspace</span>
                            <ArrowRight className="w-4 h-4" />
                          </>
                        )}
                      </button>
                    </>
                  )}

                  {/* FORGOT PASSWORD VIEW */}
                  {mode === 'forgot' && (
                    <>
                      <div className="text-xs text-text-muted leading-relaxed">
                        Enter your registered email address to receive a secure password recovery token.
                      </div>
                      <div>
                        <label className="block text-xs font-mono font-medium text-text-secondary mb-1.5">
                          Email Address
                        </label>
                        <div className="relative">
                          <Mail className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
                          <input
                            type="email"
                            required
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            placeholder="alex@acme.dev"
                            className="w-full pl-9 pr-3 py-2 bg-bg-elevated border border-border focus:border-accent-primary rounded text-xs font-mono text-text-primary placeholder:text-text-muted/60 focus:outline-none transition-colors"
                          />
                        </div>
                      </div>

                      <div className="flex gap-2">
                        <button
                          type="button"
                          onClick={() => setMode('login')}
                          className="flex-1 py-2 rounded bg-bg-elevated hover:bg-bg-hover border border-border text-xs font-mono text-text-secondary"
                        >
                          Back to Sign In
                        </button>
                        <button
                          type="submit"
                          disabled={loading}
                          className="flex-1 py-2 rounded bg-accent-primary hover:bg-accent-primary-hover text-[#0B0F14] text-xs font-mono font-bold disabled:opacity-50"
                        >
                          Send Token
                        </button>
                      </div>
                    </>
                  )}

                  {/* RESET PASSWORD VIEW */}
                  {mode === 'reset' && (
                    <>
                      <div>
                        <label className="block text-xs font-mono font-medium text-text-secondary mb-1.5">
                          Reset Token
                        </label>
                        <input
                          type="text"
                          required
                          value={resetToken}
                          onChange={(e) => setResetToken(e.target.value)}
                          placeholder="Paste token from reset email"
                          className="w-full px-3 py-2 bg-bg-elevated border border-border focus:border-accent-primary rounded text-xs font-mono text-text-primary"
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-mono font-medium text-text-secondary mb-1.5">
                          New Password
                        </label>
                        <input
                          type="password"
                          required
                          value={newPassword}
                          onChange={(e) => setNewPassword(e.target.value)}
                          placeholder="••••••••••••"
                          className="w-full px-3 py-2 bg-bg-elevated border border-border focus:border-accent-primary rounded text-xs font-mono text-text-primary"
                        />
                      </div>
                      <div className="flex gap-2">
                        <button
                          type="button"
                          onClick={() => setMode('login')}
                          className="flex-1 py-2 rounded bg-bg-elevated hover:bg-bg-hover border border-border text-xs font-mono text-text-secondary"
                        >
                          Cancel
                        </button>
                        <button
                          type="submit"
                          disabled={loading}
                          className="flex-1 py-2 rounded bg-accent-primary hover:bg-accent-primary-hover text-[#0B0F14] text-xs font-mono font-bold disabled:opacity-50"
                        >
                          Update Password
                        </button>
                      </div>
                    </>
                  )}
                </form>

                {/* GitHub OAuth Divider */}
                <div className="pt-2">
                  <div className="relative">
                    <div className="absolute inset-0 flex items-center">
                      <div className="w-full border-t border-border" />
                    </div>
                    <div className="relative flex justify-center text-xs">
                      <span className="bg-bg-secondary px-2 text-text-muted font-mono text-[10px] uppercase">
                        Or authenticate with
                      </span>
                    </div>
                  </div>

                  <div className="mt-3 grid grid-cols-1 gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        onShowToast("GitHub OAuth", "GitHub App authorization endpoint ready. In development mode, use standard credentials.", "info");
                      }}
                      className="w-full flex items-center justify-center gap-2 py-2 rounded bg-bg-elevated hover:bg-bg-hover border border-border text-xs font-mono text-text-primary transition-colors cursor-pointer"
                    >
                      <GithubIcon className="w-4 h-4 fill-current" />
                      <span>Continue with GitHub OAuth</span>
                    </button>
                  </div>
                </div>

              </div>
            </div>
          </div>

        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-border/60 py-4 px-6 text-center text-xs font-mono text-text-muted">
        <span>ShipSafe v2.4 • RFC 9106 Argon2id • OWASP Top 10 & CWE Hardened</span>
      </footer>
    </div>
  );
};
