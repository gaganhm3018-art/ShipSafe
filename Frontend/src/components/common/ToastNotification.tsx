import React, { useEffect } from 'react';
import { CheckCircle2, AlertCircle, Info, X } from 'lucide-react';

export interface ToastMessage {
  id: string;
  type: 'success' | 'error' | 'info';
  title: string;
  message?: string;
}

interface ToastProps {
  toasts: ToastMessage[];
  onDismiss: (id: string) => void;
}

export const ToastNotification: React.FC<ToastProps> = ({ toasts, onDismiss }) => {
  return (
    <div className="fixed bottom-5 right-5 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none">
      {toasts.map(toast => {
        const isSuccess = toast.type === 'success';
        const isError = toast.type === 'error';

        return (
          <div
            key={toast.id}
            className="pointer-events-auto flex items-start gap-3 p-3.5 rounded bg-bg-secondary border border-border shadow-elevated text-xs transition-all duration-200 animate-in slide-in-from-bottom-2"
          >
            {isSuccess && <CheckCircle2 className="w-4 h-4 text-accent-primary flex-shrink-0 mt-0.5" />}
            {isError && <AlertCircle className="w-4 h-4 text-severity-critical flex-shrink-0 mt-0.5" />}
            {!isSuccess && !isError && <Info className="w-4 h-4 text-accent-secondary flex-shrink-0 mt-0.5" />}

            <div className="flex-1 min-w-0">
              <div className="font-semibold text-text-primary">{toast.title}</div>
              {toast.message && (
                <div className="text-text-secondary mt-0.5 leading-snug">{toast.message}</div>
              )}
            </div>

            <button
              onClick={() => onDismiss(toast.id)}
              className="text-text-muted hover:text-text-primary transition-colors p-0.5 rounded"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        );
      })}
    </div>
  );
};
