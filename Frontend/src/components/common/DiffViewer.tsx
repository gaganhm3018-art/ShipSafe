import React, { useState } from 'react';
import { Copy, Check, GitCommit, FileDiff } from 'lucide-react';

interface DiffViewerProps {
  filePath: string;
  diffHunk: string;
  explanation?: string;
  className?: string;
}

export const DiffViewer: React.FC<DiffViewerProps> = ({
  filePath,
  diffHunk,
  explanation,
  className = ''
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(diffHunk);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const lines = diffHunk.split('\n');

  return (
    <div className={`rounded border border-border bg-[#0B0F14] overflow-hidden ${className}`}>
      {/* File & action header */}
      <div className="flex items-center justify-between px-3 py-2 bg-bg-secondary border-b border-border text-xs">
        <div className="flex items-center gap-2 font-mono text-text-secondary truncate">
          <FileDiff className="w-4 h-4 text-accent-primary flex-shrink-0" />
          <span className="text-text-primary font-medium">{filePath}</span>
          <span className="text-[10px] text-text-muted px-1.5 py-0.2 rounded bg-bg-elevated border border-border">
            Unified Diff
          </span>
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1 text-xs text-text-secondary hover:text-text-primary transition-colors px-2 py-0.5 rounded hover:bg-bg-elevated"
          title="Copy patch contents"
        >
          {copied ? (
            <>
              <Check className="w-3.5 h-3.5 text-accent-primary" />
              <span className="text-accent-primary">Patch Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5" />
              <span>Copy Patch</span>
            </>
          )}
        </button>
      </div>

      {explanation && (
        <div className="p-3 bg-bg-elevated/40 border-b border-border text-xs text-text-secondary leading-relaxed">
          <span className="font-semibold text-text-primary mr-1">Diff Scope:</span>
          {explanation}
        </div>
      )}

      {/* Diff line rendering */}
      <div className="overflow-x-auto text-xs font-mono py-1">
        <table className="w-full border-collapse">
          <tbody>
            {lines.map((line, idx) => {
              const isAdded = line.startsWith('+') && !line.startsWith('+++');
              const isRemoved = line.startsWith('-') && !line.startsWith('---');
              const isHunkHeader = line.startsWith('@@');

              let rowClass = 'text-text-secondary hover:bg-bg-secondary/40';
              let lineSign = ' ';
              let codeContent = line;

              if (isAdded) {
                rowClass = 'bg-[#45D6A0]/10 text-[#45D6A0] font-medium border-l-2 border-[#45D6A0]';
                lineSign = '+';
                codeContent = line.substring(1);
              } else if (isRemoved) {
                rowClass = 'bg-[#F04452]/10 text-[#FF7B72] font-medium border-l-2 border-[#F04452]';
                lineSign = '-';
                codeContent = line.substring(1);
              } else if (isHunkHeader) {
                rowClass = 'bg-bg-elevated/60 text-accent-secondary py-1 font-mono text-[11px]';
              }

              return (
                <tr key={idx} className={`leading-5 ${rowClass}`}>
                  {/* Sign column */}
                  <td className="w-6 text-center select-none font-bold opacity-80 pl-2">
                    {isAdded ? '+' : isRemoved ? '-' : isHunkHeader ? '' : ' '}
                  </td>

                  {/* Line index */}
                  <td className="w-10 text-right pr-3 select-none text-[11px] text-text-muted">
                    {idx + 1}
                  </td>

                  {/* Code snippet */}
                  <td className="py-0.5 pr-4 whitespace-pre font-mono">
                    {codeContent || ' '}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
