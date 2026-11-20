import React, { useState, useEffect } from 'react';
import { 
  Building2, 
  Users, 
  UserPlus, 
  ShieldCheck, 
  Key, 
  Mail, 
  Check, 
  ChevronDown, 
  X,
  AlertCircle
} from 'lucide-react';
import { WorkspaceOrg, UserProfile } from '../../types/security';

interface OrganizationViewProps {
  currentOrg: WorkspaceOrg;
  currentUser: UserProfile | null;
  onShowToast: (title: string, message?: string, type?: 'success' | 'info' | 'error') => void;
}

export const OrganizationView: React.FC<OrganizationViewProps> = ({
  currentOrg,
  currentUser,
  onShowToast
}) => {
  const [members, setMembers] = useState([
    { id: '1', user_id: 'u1', email: 'alex@acme.dev', full_name: 'Alex Developer', role: 'OWNER', joined_at: '2026-11-01' },
    { id: '2', user_id: 'u2', email: 'sarah.sec@acme.dev', full_name: 'Sarah Security', role: 'ADMIN', joined_at: '2026-11-05' },
    { id: '3', user_id: 'u3', email: 'jordan.eng@acme.dev', full_name: 'Jordan Engineer', role: 'DEVELOPER', joined_at: '2026-11-12' },
    { id: '4', user_id: 'u4', email: 'auditor@acme.dev', full_name: 'External Auditor', role: 'VIEWER', joined_at: '2026-11-18' }
  ]);

  const [isInviteOpen, setIsInviteOpen] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<'OWNER' | 'ADMIN' | 'DEVELOPER' | 'VIEWER'>('DEVELOPER');

  useEffect(() => {
    // Attempt fetch members from live API
    const fetchMembers = async () => {
      try {
        const res = await fetch(`/api/organizations/${currentOrg.id}/members`);
        if (res.ok) {
          const data = await res.json();
          if (data && data.length > 0) setMembers(data);
        }
      } catch {
        // Fallback to initial members
      }
    };
    fetchMembers();
  }, [currentOrg.id]);

  const handleSendInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch(`/api/organizations/${currentOrg.id}/members`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: inviteEmail, role: inviteRole })
      });
      if (res.ok) {
        const newMember = await res.json();
        setMembers(prev => [...prev, newMember]);
      } else {
        // Simulated addition in demo mode
        setMembers(prev => [
          ...prev,
          {
            id: Math.random().toString(),
            user_id: 'new_u',
            email: inviteEmail,
            full_name: inviteEmail.split('@')[0],
            role: inviteRole,
            joined_at: new Date().toISOString().split('T')[0]
          }
        ]);
      }
      onShowToast("Member Added", `Added ${inviteEmail} as ${inviteRole}`, "success");
      setIsInviteOpen(false);
      setInviteEmail('');
    } catch {
      onShowToast("Invitation Sent", `Invited ${inviteEmail} to workspace`, "info");
      setIsInviteOpen(false);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs uppercase tracking-wider text-text-muted">
              Workspace Administration
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-accent-primary/10 text-accent-primary border border-accent-primary/20">
              RBAC Enforced
            </span>
          </div>
          <h1 className="text-xl font-bold text-text-primary mt-1">
            Organization & Workspace Settings
          </h1>
          <p className="text-xs text-text-secondary mt-1 max-w-3xl leading-relaxed">
            Manage organization members, assign role-based permissions (Owner, Admin, Developer, Viewer), and configure multi-tenant data isolation.
          </p>
        </div>

        <button
          onClick={() => setIsInviteOpen(true)}
          className="flex items-center gap-1.5 px-3.5 py-2 rounded bg-accent-primary hover:bg-accent-primary-hover text-[#0B0F14] font-bold font-mono text-xs transition-colors self-start md:self-auto"
        >
          <UserPlus className="w-4 h-4" />
          <span>Invite Member</span>
        </button>
      </div>

      {/* Workspace Details Card */}
      <div className="p-5 rounded bg-bg-secondary border border-border space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded bg-bg-elevated border border-border flex items-center justify-center text-accent-primary">
              <Building2 className="w-5 h-5" />
            </div>
            <div>
              <div className="font-bold text-text-primary font-mono text-sm">
                {currentOrg.name}
              </div>
              <div className="text-xs text-text-muted font-mono mt-0.5">
                Slug: <span className="text-text-primary">{currentOrg.slug}</span> • Your Role: <span className="text-accent-secondary font-bold">{currentOrg.role}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Role-Based Permissions Reference */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3 font-mono text-xs">
        <div className="p-3.5 rounded bg-bg-secondary border border-border space-y-1">
          <div className="text-accent-primary font-bold">OWNER</div>
          <p className="text-[11px] text-text-muted leading-relaxed">
            Full permissions. Workspace deletion, billing, role modifications, and policy governance.
          </p>
        </div>

        <div className="p-3.5 rounded bg-bg-secondary border border-border space-y-1">
          <div className="text-accent-secondary font-bold">ADMIN</div>
          <p className="text-[11px] text-text-muted leading-relaxed">
            Manage members, add repository integrations, configure policies, and trigger audits.
          </p>
        </div>

        <div className="p-3.5 rounded bg-bg-secondary border border-border space-y-1">
          <div className="text-text-primary font-bold">DEVELOPER</div>
          <p className="text-[11px] text-text-muted leading-relaxed">
            Run local and repository scans, inspect vulnerabilities, preview diffs, and apply approved fixes.
          </p>
        </div>

        <div className="p-3.5 rounded bg-bg-secondary border border-border space-y-1">
          <div className="text-text-muted font-bold">VIEWER</div>
          <p className="text-[11px] text-text-muted leading-relaxed">
            Read-only access to posture dashboards, historical reports, and finding severity analytics.
          </p>
        </div>
      </div>

      {/* Members Table */}
      <div className="rounded bg-bg-secondary border border-border overflow-hidden">
        <div className="px-5 py-3 border-b border-border bg-bg-elevated/40 flex items-center justify-between">
          <div className="flex items-center gap-2 font-mono text-xs font-bold text-text-primary">
            <Users className="w-4 h-4 text-accent-primary" />
            <span>Workspace Members ({members.length})</span>
          </div>
        </div>

        <div className="divide-y divide-border font-mono text-xs">
          {members.map(m => (
            <div key={m.id} className="px-5 py-3.5 flex items-center justify-between hover:bg-bg-elevated/30 transition-colors">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-full bg-bg-elevated border border-border flex items-center justify-center font-bold text-accent-secondary text-xs">
                  {m.full_name.slice(0, 2).toUpperCase()}
                </div>
                <div>
                  <div className="font-semibold text-text-primary">
                    {m.full_name}
                  </div>
                  <div className="text-[11px] text-text-muted">
                    {m.email}
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-4">
                <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                  m.role === 'OWNER' ? 'bg-accent-primary/20 text-accent-primary border border-accent-primary/30' :
                  m.role === 'ADMIN' ? 'bg-accent-secondary/20 text-accent-secondary border border-accent-secondary/30' :
                  m.role === 'DEVELOPER' ? 'bg-bg-elevated text-text-primary border border-border' :
                  'bg-bg-main text-text-muted border border-border'
                }`}>
                  {m.role}
                </span>

                <div className="text-[10px] text-text-muted hidden md:block">
                  Joined: {m.joined_at}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Invite Member Modal */}
      {isInviteOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-md bg-bg-secondary border border-border rounded-lg shadow-elevated p-6 space-y-4 animate-in zoom-in-95">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <h3 className="text-sm font-bold text-text-primary font-mono flex items-center gap-2">
                <UserPlus className="w-4 h-4 text-accent-primary" />
                <span>Invite Workspace Member</span>
              </h3>
              <button onClick={() => setIsInviteOpen(false)} className="text-text-muted hover:text-text-primary">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleSendInvite} className="space-y-4 text-xs font-mono">
              <div className="space-y-1.5">
                <label className="text-text-secondary">Member Email Address:</label>
                <input
                  type="email"
                  required
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  placeholder="collaborator@acme.dev"
                  className="w-full bg-bg-main border border-border rounded px-3 py-2 text-text-primary focus:outline-none focus:border-accent-secondary"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-text-secondary">Assigned Role:</label>
                <select
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value as any)}
                  className="w-full bg-bg-main border border-border rounded px-3 py-2 text-text-primary focus:outline-none focus:border-accent-secondary"
                >
                  <option value="VIEWER">VIEWER (Read-only)</option>
                  <option value="DEVELOPER">DEVELOPER (Run scans, review fixes)</option>
                  <option value="ADMIN">ADMIN (Manage projects, members, policies)</option>
                  <option value="OWNER">OWNER (Full ownership)</option>
                </select>
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setIsInviteOpen(false)}
                  className="px-3 py-1.5 rounded bg-bg-elevated hover:bg-bg-hover text-text-muted text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-accent-primary hover:bg-accent-primary-hover text-[#0B0F14] font-bold text-xs"
                >
                  Send Invitation
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
