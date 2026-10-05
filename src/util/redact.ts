export function redactSecrets(input: string): string {
  return input
    .replace(/(Api-Key|User-Api-Key|Authorization|Cookie):\s*([^\s]+)/gi, "$1: <redacted>")
    .replace(/"http_basic_pass"\s*:\s*"[^"]*"/gi, '"http_basic_pass": "<redacted>"')
    .replace(/"cookie"\s*:\s*"[^"]*"/gi, '"cookie": "<redacted>"')
    .replace(/"extra_headers"\s*:\s*\{[^}]*\}/gi, '"extra_headers": "<redacted>"');
}

export function redactObject<T>(obj: T): T {
  const json = JSON.stringify(obj);
  const redacted = redactSecrets(json);
  try {
    return JSON.parse(redacted);
  } catch {
    return obj;
  }
}

