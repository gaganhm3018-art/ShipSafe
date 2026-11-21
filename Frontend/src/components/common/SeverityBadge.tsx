import React from 'react';
import { Severity } from '../../types/security';
import { ShieldAlert, AlertTriangle, AlertCircle, Info, ShieldCheck } from 'lucide-react';

interface SeverityBadgeProps {
  severity: Severity;
  size?: 'sm' | 'md';
  showIcon?: boolean;
  className?: string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = 'md',
  showIcon = true,
  className = ''
}) => {
  const config = {
    CRITICAL: {
      label: 'CRITICAL',
      glyph: '●',
      icon: ShieldAlert,
      bg: 'bg-[#F04452]/10',
      text: 'text-[#F04452]',
      border: 'border-[#F04452]/30',
      dot: 'bg-[#F04452]'
    },
    HIGH: {
      label: 'HIGH',
      glyph: '▲',
      icon: AlertTriangle,
      bg: 'bg-[#F28C45]/10',
      text: 'text-[#F28C45]',
      border: 'border-[#F28C45]/30',
      dot: 'bg-[#F28C45]'
    },
    MEDIUM: {
      label: 'MEDIUM',
      glyph: '◆',
      icon: AlertCircle,
      bg: 'bg-[#E9BD55]/10',
      text: 'text-[#E9BD55]',
      border: 'border-[#E9BD55]/30',
      dot: 'bg-[#E9BD55]'
    },
    LOW: {
      label: 'LOW',
      glyph: '■',
      icon: Info,
      bg: 'bg-[#65A8FF]/10',
      text: 'text-[#65A8FF]',
      border: 'border-[#65A8FF]/30',
      dot: 'bg-[#65A8FF]'
    },
    INFORMATIONAL: {
      label: 'INFO',
      glyph: '○',
      icon: ShieldCheck,
      bg: 'bg-[#8795A5]/10',
      text: 'text-[#8795A5]',
      border: 'border-[#8795A5]/30',
      dot: 'bg-[#8795A5]'
    }
  }[severity];

  const sizeClasses = size === 'sm' 
    ? 'text-[10px] px-1.5 py-0.5 tracking-wider' 
    : 'text-xs px-2.5 py-1 tracking-wide font-medium';

  const IconComponent = config.icon;

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border font-mono font-semibold uppercase ${config.bg} ${config.text} ${config.border} ${sizeClasses} ${className}`}
      title={`Severity: ${config.label}`}
    >
      {showIcon && <IconComponent className={size === 'sm' ? 'w-3 h-3' : 'w-3.5 h-3.5'} />}
      <span className="font-bold">{config.label}</span>
    </span>
  );
};
