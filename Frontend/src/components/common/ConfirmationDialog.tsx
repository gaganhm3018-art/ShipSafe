import React from 'react';
import { AlertTriangle, X, ShieldAlert, GitBranch } from 'lucide-react';

interface ConfirmationDialogProps {
  isOpen: boolean;
  title: string;
  description: string;
  confirmLabel: string;
  cancelLabel?: string;
  variant?: 'danger' | 'warning' | 'primary';
  details?: {
    file?: string;
    findingId?: string;
    branch?: string;
  };
  onConfirm: () => void;
  onCancel: () => void;
}

export const ConfirmationDialog: React.FC<ConfirmationDialogProps> = ({
  isOpen,
  title,
  description,
  confirmLabel,
  cancelLabel = 'Cancel',
  variant = 'primary',
  details,
  onConfirm,
  onCancel
}) => {
  if (!isOpen) return null;

  const confirmBtnStyles = {
    danger: 'bg-severity-critical hover:bg-severity-critical/90 text-white',
    warning: 'bg-severity-high hover:bg-severity-high/90 text-white',
    primary: 'bg-accent-primary hover:bg-accent-primary-hover text-[#0B0F14] font-semibold'
  }[variant];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="w-full max-w-md bg-bg-secondary border border-border rounded-lg shadow-elevated overflow-hidden animate-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-border bg-bg-elevated/40">
          <div className="flex items-center gap-2.5">
            {variant === 'danger' ? (
              <ShieldAlert className="w-5 h-5 text-severity-critical" />
            ) : (
              <AlertTriangle className="w-5 h-5 text-severity-high" />
            )}
            <h3 className="text-sm font-semibold text-text-primary tracking-tight">
              {title}
            </h3>
          </div>
          <button
            onClick={onCancel}
            className="text-text-muted hover:text-text-primary transition-colors p-1 rounded hover:bg-bg-elevated"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 text-xs text-text-secondary space-y-3">
          <p className="leading-relaxed text-text-primary">
            {description}
          </p>

          {details && (
            <div className="p-3 rounded bg-[#0D1219] border border-border font-mono text-[11px] space-y-1.5 text-text-muted">
              {details.file && (
                <div className="flex items-center justify-between">
                  <span>Target File:</span>
                  <span className="text-text-primary font-medium">{details.file}</span>
                </div>
              )}
              {details.findingId && (
                <div className="flex items-center justify-between">
                  <span>Finding ID:</span>
                  <span className="text-accent-secondary">{details.findingId}</span>
                </div>
              )}
              {details.branch && (
                <div className="flex items-center justify-between">
                  <span>Branch:</span>
                  <span className="text-text-primary flex items-center gap-1">
                    <GitBranch className="w-3 h-3 text-text-muted" />
                    {details.branch}
                  </span>
                </div>
              )}
            </div>
          )}

          <div className="text-[11px] text-text-muted bg-bg-elevated/30 p-2.5 rounded border border-border/60">
            Applying this modification creates an atomic patch and initiates an automatic security rescan to confirm vulnerability resolution.
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-2 px-5 py-3.5 bg-bg-elevated/60 border-t border-border">
          <button
            onClick={onCancel}
            className="px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary hover:bg-bg-elevated rounded border border-border transition-colors"
          >
            {cancelLabel}
          </button>
          <button
            onClick={onConfirm}
            className={`px-4 py-1.5 text-xs rounded transition-colors shadow-subtle ${confirmBtnStyles}`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
};
