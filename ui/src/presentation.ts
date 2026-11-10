import type { Command } from './protocol.js';

/** POSIX display quoting preserves argument boundaries; execution still uses argv directly. */
export function quoteArgument(argument: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(argument) ? argument : `'${argument.replaceAll("'", "'\\''")}'`;
}
export function commandPreview(command: Command): string {
  return command.kind === 'argv' ? command.argv.map(quoteArgument).join(' ') : command.script;
}
export function remainingTime(expiresAt: number, now = Math.floor(Date.now()/1000)): string {
  const seconds = Math.max(0,expiresAt-now);
  if (seconds === 0) return 'Expired';
  const hours = Math.floor(seconds/3600);
  const minutes = Math.floor((seconds%3600)/60);
  return hours > 0 ? `${hours}h ${minutes}m remaining` : `${Math.floor(seconds/60)}:${String(seconds%60).padStart(2,'0')} remaining`;
}
