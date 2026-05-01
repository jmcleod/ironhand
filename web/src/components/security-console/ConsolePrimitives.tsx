import * as React from 'react';
import { cn } from '@/lib/utils';

type Tone = 'default' | 'success' | 'warning' | 'danger' | 'muted';

const toneClasses: Record<Tone, string> = {
  default: 'border-primary/25 bg-primary/10 text-primary',
  success: 'border-green-500/25 bg-green-500/10 text-green-400',
  warning: 'border-amber-500/25 bg-amber-500/10 text-amber-400',
  danger: 'border-red-500/25 bg-red-500/10 text-red-400',
  muted: 'border-border bg-muted/60 text-muted-foreground',
};

export function ConsolePanel({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <section className={cn('console-panel rounded-lg', className)} {...props}>
      {children}
    </section>
  );
}

export function ConsolePanelHeader({
  title,
  eyebrow,
  action,
  className,
}: {
  title: React.ReactNode;
  eyebrow?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('flex items-start justify-between gap-4', className)}>
      <div className="min-w-0">
        {eyebrow && <p className="console-kicker mb-1">{eyebrow}</p>}
        <h2 className="truncate text-sm font-semibold tracking-[0.12em] text-foreground uppercase">
          {title}
        </h2>
      </div>
      {action}
    </div>
  );
}

export function StatusPill({
  tone = 'default',
  children,
  className,
}: {
  tone?: Tone;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cn(
        'inline-flex h-6 items-center gap-1.5 rounded-full border px-2.5 text-xs font-semibold',
        toneClasses[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

export function MetricBlock({
  label,
  value,
  detail,
  tone = 'default',
  className,
}: {
  label: React.ReactNode;
  value: React.ReactNode;
  detail?: React.ReactNode;
  tone?: Tone;
  className?: string;
}) {
  const valueTone = {
    default: 'text-foreground',
    success: 'text-green-400',
    warning: 'text-amber-400',
    danger: 'text-red-400',
    muted: 'text-muted-foreground',
  }[tone];

  return (
    <div className={cn('space-y-1', className)}>
      <p className="console-kicker">{label}</p>
      <div className={cn('text-3xl font-semibold leading-none tracking-normal', valueTone)}>
        {value}
      </div>
      {detail && <p className="text-xs text-muted-foreground">{detail}</p>}
    </div>
  );
}

export function ConsoleTable({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('overflow-hidden rounded-lg border border-border/80', className)}>
      <table className="w-full text-left text-sm">{children}</table>
    </div>
  );
}

export function ConsoleTh({
  children,
  className,
  ...props
}: React.ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th className={cn('px-4 py-2 text-[0.68rem] font-semibold uppercase tracking-[0.14em] text-muted-foreground', className)} {...props}>
      {children}
    </th>
  );
}

export function ConsoleTd({
  children,
  className,
  ...props
}: React.TdHTMLAttributes<HTMLTableCellElement>) {
  return <td className={cn('border-t border-border/70 px-4 py-3', className)} {...props}>{children}</td>;
}
