/** Match the backend's default for single-column threat indicator feeds. */
export function firstRowIsHeader(content: string): boolean {
  // Skip a leading `#` comment block the way the backend parser does
  // (FileParser::first_data_line): only when the content opens with one.
  const lines = content.replace(/^\uFEFF/, '').split(/\r?\n/);
  const skipComments = lines.find((line) => line.trim())?.startsWith('#') ?? false;
  const first = lines.find((line) => line.trim() && !(skipComments && line.startsWith('#')))?.trim() ?? '';
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
