import React from 'react';

interface SecurityMetricProps {
  label: string;
  value: string | number;
  subtext?: string;
  trend?: 'danger' | 'warning' | 'safe' | 'neutral';
  trendText?: string;
  badge?: React.ReactNode;
}

export const SecurityMetric: React.FC<SecurityMetricProps> = ({
  label,
  value,
  subtext,
  trend = 'neutral',
  trendText,
  badge
}) => {
  const trendColor = {
    danger: 'text-severity-critical',
    warning: 'text-severity-high',
    safe: 'text-accent-primary',
    neutral: 'text-text-secondary'
  }[trend];

  return (
    <div className="bg-bg-secondary border border-border rounded p-4 flex flex-col justify-between hover:border-border-active transition-colors">
      <div className="flex items-center justify-between gap-2 mb-2">
        <span className="text-xs font-medium text-text-secondary uppercase tracking-wider">
          {label}
        </span>
        {badge}
      </div>
      <div className="flex items-baseline gap-2">
        <span className="text-2xl font-bold font-mono tracking-tight text-text-primary">
          {value}
        </span>
        {trendText && (
          <span className={`text-xs font-mono font-medium ${trendColor}`}>
            {trendText}
          </span>
        )}
      </div>
      {subtext && (
        <span className="text-xs text-text-muted mt-1 font-mono truncate">
          {subtext}
        </span>
      )}
    </div>
  );
};
