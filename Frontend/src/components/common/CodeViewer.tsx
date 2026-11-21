import React, { useState } from 'react';
import { CodeSnippet } from '../../types/security';
import { Copy, Check, FileCode, AlertCircle } from 'lucide-react';

interface CodeViewerProps {
  filePath: string;
  snippet: CodeSnippet;
  language?: string;
  className?: string;
}

export const CodeViewer: React.FC<CodeViewerProps> = ({
  filePath,
  snippet,
  language = 'python',
  className = ''
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    const textToCopy = snippet.lines.map(l => l.code).join('\n');
    navigator.clipboard.writeText(textToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={`rounded border border-border bg-[#0D1219] overflow-hidden ${className}`}>
      {/* File path header bar */}
      <div className="flex items-center justify-between px-3 py-2 bg-bg-secondary border-b border-border text-xs">
        <div className="flex items-center gap-2 font-mono text-text-secondary truncate">
          <FileCode className="w-4 h-4 text-accent-secondary flex-shrink-0" />
          <span className="text-text-primary font-medium">{filePath}</span>
          <span className="text-text-muted">:{snippet.targetLine}</span>
        </div>
        <div className="flex items-center gap-3">
          <span className="font-mono text-[10px] text-text-muted uppercase px-1.5 py-0.5 rounded bg-bg-elevated border border-border">
            {language}
          </span>
          <button
            onClick={handleCopy}
            className="flex items-center gap-1 text-xs text-text-secondary hover:text-text-primary transition-colors px-1.5 py-0.5 rounded hover:bg-bg-elevated"
            title="Copy code snippet"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-accent-primary" />
                <span className="text-accent-primary">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Code line rows */}
      <div className="overflow-x-auto text-xs font-mono py-2">
        <table className="w-full border-collapse">
          <tbody>
            {snippet.lines.map((lineObj) => {
              const isTarget = lineObj.isTarget || lineObj.line === snippet.targetLine;
              return (
                <tr
                  key={lineObj.line}
                  className={`group transition-colors ${
                    isTarget 
                      ? 'bg-severity-critical/15 text-text-primary border-l-2 border-severity-critical font-medium' 
                      : 'hover:bg-bg-secondary/40 text-text-secondary'
                  }`}
                >
                  {/* Line number gutter */}
                  <td className={`select-none text-right pr-4 pl-3 py-0.5 w-12 text-text-muted ${
                    isTarget ? 'text-severity-critical font-bold' : ''
                  }`}>
                    <div className="flex items-center justify-end gap-1">
                      {isTarget && (
                        <AlertCircle className="w-3 h-3 text-severity-critical flex-shrink-0" />
                      )}
                      <span>{lineObj.line}</span>
                    </div>
                  </td>

                  {/* Code line content */}
                  <td className="py-0.5 pr-4 whitespace-pre font-mono">
                    <span className={isTarget ? 'text-[#FF7B72]' : 'text-text-primary'}>
                      {lineObj.code || ' '}
                    </span>
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
