/**
 * Pack language-id → App SAST family resolution (GAP-040).
 *
 * Drobon-Dataset uses 115 language ids; the App catalog resolves 47 directly
 * and 2 by its own declared alias. The remaining 66 are configuration formats
 * that had NO App family at all, which made 160 SAST rules unreachable at
 * runtime (`interop/APP_CONFORMANCE.md`). This module closes the gate without
 * copying dataset bytes: it is a declared mapping plus one new App family
 * (`config-file`) whose detection lives in `scans/sast/languages.ts`.
 *
 * Honesty note: a config id mapped to `config-file` shares ONE family with the
 * other config ids. That is coarser than a dedicated family per daemon, so a
 * rule tagged `nginx` can also be evaluated on an `sshd_config` file — its own
 * pattern still decides whether it fires. No rule is dropped, and every
 * resolution is declared here rather than guessed at load time.
 */

export const CONFIG_FAMILY = 'config-file';

/** Explicit aliases. Anything absent here must already be an App catalog id. */
export const PACK_LANGUAGE_ALIASES: Readonly<Record<string, string>> = Object.freeze({
  // Two aliases the dataset already declares.
  shell: 'shell-posix',
  gha: 'github-actions',
  // YAML-shaped infra manifests: the App detects these as `yaml`.
  k8s: 'yaml',
  compose: 'yaml',
  gitlab: 'yaml',
  istio: 'yaml',
  elastic: 'yaml',
  // Source-like ids without a catalog entry: use the config family so the
  // file is still analyzed (maturity CONFIG_ANALYSIS).
  tcl: CONFIG_FAMILY,
  basic: CONFIG_FAMILY,
  pascal: CONFIG_FAMILY,
  vba: CONFIG_FAMILY,
  awk: CONFIG_FAMILY,
  cmd: CONFIG_FAMILY,
  asp: CONFIG_FAMILY,
  coldfusion: CONFIG_FAMILY,
  blade: CONFIG_FAMILY,
  ejs: CONFIG_FAMILY,
  handlebars: CONFIG_FAMILY,
  jinja: CONFIG_FAMILY,
  jsp: CONFIG_FAMILY,
  pug: CONFIG_FAMILY,
  smarty: CONFIG_FAMILY,
  twig: CONFIG_FAMILY,
  gradle: CONFIG_FAMILY,
  properties: CONFIG_FAMILY,
  ini: CONFIG_FAMILY,
  // Server / daemon configuration formats.
  sshd: CONFIG_FAMILY,
  nginx: CONFIG_FAMILY,
  apache: CONFIG_FAMILY,
  postgres: CONFIG_FAMILY,
  mysql: CONFIG_FAMILY,
  bind: CONFIG_FAMILY,
  samba: CONFIG_FAMILY,
  systemd: CONFIG_FAMILY,
  nfs: CONFIG_FAMILY,
  redis: CONFIG_FAMILY,
  vault: CONFIG_FAMILY,
  vsftpd: CONFIG_FAMILY,
  haproxy: CONFIG_FAMILY,
  postfix: CONFIG_FAMILY,
  sudo: CONFIG_FAMILY,
  grafana: CONFIG_FAMILY,
  graylog: CONFIG_FAMILY,
  influx: CONFIG_FAMILY,
  cassandra: CONFIG_FAMILY,
  couchdb: CONFIG_FAMILY,
  dovecot: CONFIG_FAMILY,
  jmx: CONFIG_FAMILY,
  kafka: CONFIG_FAMILY,
  memcached: CONFIG_FAMILY,
  mongo: CONFIG_FAMILY,
  mosquitto: CONFIG_FAMILY,
  neo4j: CONFIG_FAMILY,
  openvpn: CONFIG_FAMILY,
  rabbitmq: CONFIG_FAMILY,
  logrotate: CONFIG_FAMILY,
  rsyslog: CONFIG_FAMILY,
  squid: CONFIG_FAMILY,
  traefik: CONFIG_FAMILY,
  supervisor: CONFIG_FAMILY,
  unbound: CONFIG_FAMILY,
  proftpd: CONFIG_FAMILY,
  logindefs: CONFIG_FAMILY,
  pam: CONFIG_FAMILY,
  caddy: CONFIG_FAMILY,
  consul: CONFIG_FAMILY,
  minio: CONFIG_FAMILY,
  slapd: CONFIG_FAMILY,
});

/**
 * Convert a pack rule's `languages` array into App family ids.
 * Returns `undefined` for universal rules (no `languages` field), which the
 * engine then evaluates on every analyzed file. Unknown ids are dropped only
 * if they are neither a catalog id nor an alias — callers can detect that
 * with `unresolvedPackLanguageIds()` and fail loudly.
 */
export function resolvePackLanguages(languages: unknown, catalogIds: ReadonlySet<string>): string[] | undefined {
  if (languages === undefined) return undefined;
  if (!Array.isArray(languages)) return [];
  const out: string[] = [];
  for (const id of languages) {
    if (typeof id !== 'string') continue;
    const resolved = PACK_LANGUAGE_ALIASES[id] ?? id;
    if (catalogIds.has(resolved) && !out.includes(resolved)) out.push(resolved);
  }
  return out;
}

/** Ids that still have no App family (should be empty against the current pack). */
export function unresolvedPackLanguageIds(ids: readonly string[], catalogIds: ReadonlySet<string>): string[] {
  return [...new Set(ids)]
    .filter((id) => !catalogIds.has(PACK_LANGUAGE_ALIASES[id] ?? id))
    .sort();
}
