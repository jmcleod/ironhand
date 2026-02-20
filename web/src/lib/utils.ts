import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Returns the CSP nonce injected by the server into a
 * `<meta name="csp-nonce">` tag in the HTML head. Components that create
 * dynamic `<style>` elements must add `nonce={getCSPNonce()}` so the styles
 * are permitted by the Content-Security-Policy.
 */
export function getCSPNonce(): string | undefined {
  const meta = document.querySelector('meta[name="csp-nonce"]');
  return meta?.getAttribute('content') ?? undefined;
}
