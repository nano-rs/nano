// SPDX-License-Identifier: AGPL-3.0-or-later

/** Match the backend's default for single-column threat indicator feeds. */
export function firstRowIsHeader(content: string): boolean {
  const first = content.replace(/^\uFEFF/, '').split(/\r?\n/).find((line) => line.trim())?.trim() ?? '';
  if (first.includes(',')) return true;
  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const hash = /^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/;
  const domain = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  const email = /^[^\s@]+@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
  const cidr = /^(.+)\/(\d{1,3})$/;
  const cidrMatch = first.match(cidr);
  return !(ipv4.test(first) && first.split('.').every((part) => Number(part) <= 255)
    || first.includes(':') && /^(?:[a-fA-F0-9:]+)$/.test(first)
    || cidrMatch && (ipv4.test(cidrMatch[1]) || cidrMatch[1].includes(':'))
    || /^https?:\/\/[^\s/]+/.test(first) || hash.test(first) || email.test(first) || domain.test(first));
}

export function urlFirstRowIsHeader(url: string): boolean {
  return !/\.txt(?:[?#]|$)/i.test(url);
}
