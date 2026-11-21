import React from 'react';
import { Command, X, Keyboard } from 'lucide-react';

interface KeyboardShortcutsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const KeyboardShortcutsModal: React.FC<KeyboardShortcutsModalProps> = ({
  isOpen,
  onClose
}) => {
  if (!isOpen) return null;

  const shortcuts = [
    { key: 'J / K', description: 'Navigate down / up across security findings' },
    { key: 'Enter', description: 'Inspect selected vulnerability details' },
    { key: 'R', description: 'Open AI-assisted remediation diff viewer' },
    { key: 'S', description: 'Trigger immediate repository security rescan' },
    { key: '/', description: 'Focus search & filter input' },
    { key: 'E', description: 'Export findings as standard SARIF 2.1.0' },
    { key: 'Esc', description: 'Close modals, drawers, and active inspectors' }
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="w-full max-w-md bg-bg-secondary border border-border rounded-lg shadow-elevated overflow-hidden animate-in zoom-in-95 duration-150">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border bg-bg-elevated/40">
          <div className="flex items-center gap-2">
            <Keyboard className="w-4 h-4 text-accent-secondary" />
            <h3 className="text-sm font-semibold text-text-primary">
              Developer Keyboard Shortcuts
            </h3>
          </div>
          <button
            onClick={onClose}
            className="text-text-muted hover:text-text-primary transition-colors p-1 rounded hover:bg-bg-elevated"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-3">
          <div className="text-xs text-text-secondary mb-3">
            ShipSafe is engineered for keyboard-first developer navigation.
          </div>

          <div className="space-y-2">
            {shortcuts.map((sc, i) => (
              <div
                key={i}
                className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-bg-elevated/40 text-xs"
              >
                <span className="text-text-secondary">{sc.description}</span>
                <kbd className="px-2 py-0.5 rounded bg-bg-main border border-border font-mono text-[11px] font-semibold text-accent-secondary shadow-sm">
                  {sc.key}
                </kbd>
              </div>
            ))}
          </div>
        </div>

        <div className="px-5 py-3 bg-bg-elevated/60 border-t border-border flex justify-end">
          <button
            onClick={onClose}
            className="px-3.5 py-1.5 text-xs bg-bg-main border border-border hover:bg-bg-elevated rounded text-text-primary transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
