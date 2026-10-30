import type { FindingSeverity } from '@drobon/shared';

/**
 * UNIVERSAL LANGUAGE & PLATFORM CATALOG (SAST v2).
 *
 * The honest language model for the ONE shared SAST engine: the engine
 * remains the same deterministic, read-only, line-based pattern engine
 * (see `rules.ts`) — this catalog adds:
 *
 * - DETECTION for 53 language/configuration families (extension,
 *   exact filename, shebang, and two documented content tie-breaks), so
 *   polyglot repositories are analyzed as one snapshot;
 * - HONEST MATURITY per family. Lexical matching is supplemented by a
 *   bounded shallow flow, several limited syntax parsers, and a bounded JS/TS project pass. None
 *   supplies complete semantic/dataflow or cross-file analysis, therefore
 *   NO family is labelled FULL. Maturity is an audit statement, never marketing:
 *
 *     PARTIAL          real security rules + evidence + fingerprint +
 *                      remediation + retest + report/SARIF + tests, but
 *                      pattern-based only (not full-depth SAST)
 *     CONFIG_ANALYSIS  configuration security analysis (same pipeline)
 *     SYNTAX_ONLY      detected and catalogued, but no security rules
 *                      (files are skipped and counted, never analysed)
 *     UNSUPPORTED      honest refusal: skipped and counted
 *     FULL             parser + AST + semantic/dataflow depth — reached
 *                      by NO family yet (documented, never faked)
 *
 * - FRAMEWORK MARKERS for build/manifest files so framework-aware
 *   rules (Electron, Django, Flask, React sinks) and detection tests
 *   have a deterministic foundation.
 *
 * This module is APPLICATION LOGIC, not a vulnerability database: it
 * contains no CVE/NVD/GHSA/OSV/KEV/EPSS data (the dataset lock holds —
 * docs/SAST.md).
 */

import { AST_SUPPORTED_FAMILIES } from './astProfiles.js';

export type SastMaturity = 'FULL' | 'PARTIAL' | 'SYNTAX_ONLY' | 'CONFIG_ANALYSIS' | 'UNSUPPORTED';

export type SastPlatform =
  | 'web'
  | 'backend'
  | 'mobile'
  | 'desktop'
  | 'native'
  | 'config'
  | 'infra'
  | 'data';

export interface SastLanguageFamily {
  /** Stable family id used by rule gating (`SastRule.languages`). */
  readonly id: string;
  readonly label: string;
  readonly maturity: SastMaturity;
  readonly platforms: readonly SastPlatform[];
  /** Case-insensitive extensions (leading dot). */
  readonly extensions?: readonly string[];
  /** Exact basenames (lowercased) — e.g. `dockerfile`. */
  readonly filenames?: readonly string[];
  /** First-line shebang interpreter matchers (lowercased, `env` resolved). */
  readonly shebangs?: readonly string[];
  /** Honest scope note surfaced in docs/tests. */
  readonly note: string;
}

/**
 * The closed catalog, ordered for stable iteration. Detection happens
 * over this table only — nothing client-facing can add a family.
 */
export const SAST_LANGUAGE_CATALOG: readonly SastLanguageFamily[] = [
  // ---- P0: primary application languages (PARTIAL: real rules) ----
  { id: 'javascript', label: 'JavaScript', maturity: 'PARTIAL', platforms: ['web', 'backend', 'desktop'], extensions: ['.js', '.mjs', '.cjs'], shebangs: ['node'], note: 'Pattern rules: command/code/SQL injection shapes, raw-HTML sinks, weak hash, Electron nodeIntegration, universal credential heuristic.' },
  { id: 'typescript', label: 'TypeScript', maturity: 'PARTIAL', platforms: ['web', 'backend'], extensions: ['.ts'], note: 'Same rule family as JavaScript.' },
  { id: 'jsx', label: 'JSX', maturity: 'PARTIAL', platforms: ['web'], extensions: ['.jsx'], note: 'Includes React `__html` sink detection.' },
  { id: 'tsx', label: 'TSX', maturity: 'PARTIAL', platforms: ['web'], extensions: ['.tsx'], note: 'Includes React `__html` sink detection.' },
  { id: 'python', label: 'Python', maturity: 'PARTIAL', platforms: ['backend', 'desktop'], extensions: ['.py', '.pyw'], shebangs: ['python', 'python3'], note: 'eval/exec with interpolation, os.system/os.popen, unsafe deserialization (pickle/marshal/yaml.load), weak hash, Django raw SQL, Flask debug.' },
  { id: 'java', label: 'Java', maturity: 'PARTIAL', platforms: ['backend', 'mobile', 'desktop'], extensions: ['.java'], note: 'JVM command injection, SQL concat, weak MessageDigest, Android world-readable storage, WebView settings.' },
  { id: 'kotlin', label: 'Kotlin', maturity: 'PARTIAL', platforms: ['mobile', 'backend'], extensions: ['.kt', '.kts'], note: 'JVM + Android rule family (shared with Java).' },
  { id: 'c', label: 'C', maturity: 'PARTIAL', platforms: ['native', 'desktop'], extensions: ['.c', '.h'], note: 'Dangerous memory functions (gets/strcpy/strcat/sprintf/vsprintf).' },
  { id: 'cpp', label: 'C++', maturity: 'PARTIAL', platforms: ['native', 'desktop'], extensions: ['.cc', '.cpp', '.cxx', '.hpp', '.hh', '.hxx'], note: 'Same memory-safety rule family as C.' },
  { id: 'csharp', label: 'C#', maturity: 'PARTIAL', platforms: ['backend', 'desktop'], extensions: ['.cs'], note: 'Process.Start with concat, SqlCommand concat, weak MD5/SHA-1 providers.' },
  { id: 'go', label: 'Go', maturity: 'PARTIAL', platforms: ['backend'], extensions: ['.go'], note: 'exec.Command with fmt.Sprintf, md5/sha1.New.' },
  { id: 'php', label: 'PHP', maturity: 'PARTIAL', platforms: ['backend'], extensions: ['.php', '.phtml'], note: 'shell_exec/system/passthru with concat, backtick execution, mysql/mysqli query concat.' },
  { id: 'rust', label: 'Rust', maturity: 'PARTIAL', platforms: ['backend', 'native', 'desktop'], extensions: ['.rs'], note: 'Command::new/.arg with format! interpolation.' },
  { id: 'ruby', label: 'Ruby', maturity: 'PARTIAL', platforms: ['backend'], extensions: ['.rb'], filenames: ['gemfile', 'rakefile'], shebangs: ['ruby'], note: 'system/backticks with #{...} interpolation.' },
  { id: 'swift', label: 'Swift', maturity: 'PARTIAL', platforms: ['mobile', 'desktop'], extensions: ['.swift'], note: 'Weak CommonCrypto/CryptoKit algorithms (DES/3DES/RC4/MD5/SHA-1).' },

  // ---- P1 (PARTIAL: real rules) ----
  { id: 'dart', label: 'Dart', maturity: 'PARTIAL', platforms: ['mobile'], extensions: ['.dart'], note: 'Process.run/start with concat (Flutter backend logic).' },
  { id: 'scala', label: 'Scala', maturity: 'PARTIAL', platforms: ['backend'], extensions: ['.scala'], note: 'JVM rule family.' },
  { id: 'objc', label: 'Objective-C', maturity: 'PARTIAL', platforms: ['mobile', 'desktop'], extensions: ['.m'], note: 'Content tie-break with MATLAB (Objective-C markers win). Memory-safety rule family.' },
  { id: 'objcpp', label: 'Objective-C++', maturity: 'PARTIAL', platforms: ['mobile', 'desktop'], extensions: ['.mm'], note: 'Memory-safety rule family.' },
  { id: 'lua', label: 'Lua', maturity: 'PARTIAL', platforms: ['backend', 'desktop'], extensions: ['.lua'], shebangs: ['lua'], note: 'os.execute/io.popen with `..` concat.' },
  { id: 'solidity', label: 'Solidity', maturity: 'PARTIAL', platforms: ['backend'], extensions: ['.sol'], note: 'delegatecall/selfdestruct usage signals (conservative, MEDIUM).' },
  { id: 'r', label: 'R', maturity: 'PARTIAL', platforms: ['data'], extensions: ['.r'], shebangs: ['rscript'], note: 'system(paste(...)) dynamic command construction.' },
  { id: 'elixir', label: 'Elixir', maturity: 'PARTIAL', platforms: ['backend'], extensions: ['.ex', '.exs'], shebangs: ['elixir'], note: 'Code.eval_string/eval_quoted.' },
  { id: 'erlang', label: 'Erlang', maturity: 'PARTIAL', platforms: ['backend'], extensions: ['.erl', '.hrl'], note: 'os:cmd with ++ concat.' },
  { id: 'clojure', label: 'Clojure', maturity: 'UNSUPPORTED', platforms: ['backend'], extensions: ['.clj', '.cljs', '.cljc', '.edn'], note: 'Detected and counted; no rules yet — never guessed at.' },
  { id: 'groovy', label: 'Groovy', maturity: 'PARTIAL', platforms: ['backend'], extensions: ['.groovy'], note: 'JVM rule family (incl. Gradle scripts).' },
  { id: 'perl', label: 'Perl', maturity: 'PARTIAL', platforms: ['backend'], extensions: ['.pl', '.pm'], shebangs: ['perl'], note: 'system/backticks with $ interpolation.' },
  { id: 'haskell', label: 'Haskell', maturity: 'UNSUPPORTED', platforms: ['backend'], extensions: ['.hs'], note: 'Detected and counted; no rules yet.' },
  { id: 'ocaml', label: 'OCaml', maturity: 'UNSUPPORTED', platforms: ['backend'], extensions: ['.ml', '.mli'], note: 'Detected and counted; no rules yet.' },
  { id: 'julia', label: 'Julia', maturity: 'PARTIAL', platforms: ['data'], extensions: ['.jl'], shebangs: ['julia'], note: 'run(`...$interp`) command construction.' },
  { id: 'vbnet', label: 'Visual Basic / VB.NET', maturity: 'PARTIAL', platforms: ['desktop', 'backend'], extensions: ['.vb'], note: 'Shell(...) with & concat, weak MD5/SHA-1 providers.' },
  { id: 'apex', label: 'Apex', maturity: 'PARTIAL', platforms: ['backend'], extensions: ['.cls', '.trigger'], note: 'Database.query with concat (SOQL injection shape).' },

  // ---- P2: configuration / data formats ----
  { id: 'bash', label: 'Bash', maturity: 'PARTIAL', platforms: ['config', 'backend'], shebangs: ['bash'], note: 'Shebang-detected (#!/… bash); eval with variable expansion.' },
  { id: 'shell-posix', label: 'POSIX Shell', maturity: 'PARTIAL', platforms: ['config', 'backend'], extensions: ['.sh'], shebangs: ['sh'], note: 'eval with variable expansion.' },
  { id: 'powershell', label: 'PowerShell', maturity: 'PARTIAL', platforms: ['config', 'desktop'], extensions: ['.ps1', '.psm1'], shebangs: ['pwsh'], note: 'Invoke-Expression with variables.' },
  { id: 'sql', label: 'SQL', maturity: 'CONFIG_ANALYSIS', platforms: ['data'], extensions: ['.sql'], note: 'Dynamic SQL execution shapes (EXEC(@…), EXECUTE IMMEDIATE … ||).' },
  { id: 'html', label: 'HTML', maturity: 'SYNTAX_ONLY', platforms: ['web'], extensions: ['.html', '.htm'], note: 'Detected; no security rules yet — skipped and counted honestly.' },
  { id: 'css', label: 'CSS', maturity: 'SYNTAX_ONLY', platforms: ['web'], extensions: ['.css', '.scss', '.less'], note: 'Detected; no security rules yet — skipped and counted honestly.' },
  { id: 'xml', label: 'XML', maturity: 'CONFIG_ANALYSIS', platforms: ['config'], extensions: ['.xml', '.xsd', '.xsl'], note: 'External-entity (XXE) DTD detection.' },
  { id: 'yaml', label: 'YAML', maturity: 'CONFIG_ANALYSIS', platforms: ['config', 'infra'], extensions: ['.yml', '.yaml'], note: 'Privileged-container detection; GitHub-Actions files are content-tie-broken to their own family.' },
  { id: 'json', label: 'JSON', maturity: 'CONFIG_ANALYSIS', platforms: ['config'], extensions: ['.json'], note: 'Universal credential heuristic applies (package.json is also a framework marker).' },
  { id: 'dockerfile', label: 'Dockerfile', maturity: 'CONFIG_ANALYSIS', platforms: ['infra'], filenames: ['dockerfile'], extensions: ['.dockerfile'], note: 'Pipe-to-shell install detection.' },
  { id: 'terraform', label: 'Terraform / HCL', maturity: 'CONFIG_ANALYSIS', platforms: ['infra'], extensions: ['.tf', '.hcl', '.tfvars'], note: 'Open-world ingress CIDR detection.' },
  { id: 'github-actions', label: 'GitHub Actions YAML', maturity: 'CONFIG_ANALYSIS', platforms: ['infra'], note: 'Content tie-break from YAML (`runs-on:` + `jobs:`/`on:` — snapshot paths cannot contain `.github` dotfile segments). Dangerous `permissions: write-all`.' },
  { id: 'android-manifest', label: 'AndroidManifest.xml', maturity: 'CONFIG_ANALYSIS', platforms: ['mobile'], filenames: ['androidmanifest.xml'], note: 'Exported-component detection.' },

  // ---- Dataset configuration formats (GAP-040 reachability) ----
  // One shared family for the 60+ daemon/template ids used by the external
  // Drobon-Dataset packs. CONFIG_ANALYSIS keeps these files analyzed by the
  // same bounded, lexical engine; the pack rule's own pattern decides whether
  // it fires. Detection is by exact filename or a non-conflicting extension,
  // so existing family detection is unchanged.
  { id: 'config-file', label: 'Dataset configuration formats', maturity: 'CONFIG_ANALYSIS', platforms: ['config', 'infra'], extensions: ['.ini', '.conf', '.cfg', '.properties', '.tcl', '.bas', '.pas', '.vba', '.awk', '.bat', '.cmd', '.asp', '.cfm', '.gradle', '.service', '.socket', '.timer'], filenames: ['nginx.conf', 'httpd.conf', 'sshd_config', 'my.cnf', 'postgresql.conf', 'redis.conf', 'named.conf', 'smb.conf', 'docker-compose.yml', 'docker-compose.yaml', 'build.gradle', 'build.gradle.kts', 'settings.gradle', 'jenkinsfile', 'vault.hcl', 'grafana.ini', 'logrotate.conf', 'rsyslog.conf', 'squid.conf', 'traefik.toml', 'supervisord.conf', 'sudoers', 'login.defs', 'proftpd.conf', 'unbound.conf', 'caddyfile', 'mongod.conf', 'haproxy.cfg', 'postfix.cf'], note: 'Shared family for dataset-tagged server/template config ids; rules are gated by their own patterns, never by a claimed parser.' },

  // ---- Optional / honestly unsupported (audited, refused) ----
  { id: 'assembly', label: 'Assembly', maturity: 'UNSUPPORTED', platforms: ['native'], extensions: ['.s', '.asm'], note: 'Detected and counted; source-only SAST cannot make memory-safety claims here.' },
  { id: 'matlab', label: 'MATLAB', maturity: 'UNSUPPORTED', platforms: ['data'], note: '`.m` defaults to Objective-C unless MATLAB markers win the content tie-break; then still UNSUPPORTED (no rules).' },
  { id: 'fortran', label: 'Fortran', maturity: 'UNSUPPORTED', platforms: ['native'], extensions: ['.f', '.f90', '.f95', '.f03'], note: 'Detected and counted; no rules yet.' },
  { id: 'cobol', label: 'COBOL', maturity: 'UNSUPPORTED', platforms: ['backend'], extensions: ['.cbl', '.cob'], note: 'Detected and counted; no rules yet.' },
  { id: 'crystal', label: 'Crystal', maturity: 'UNSUPPORTED', platforms: ['backend'], extensions: ['.cr'], note: 'Detected and counted; no rules yet.' },
  { id: 'zig', label: 'Zig', maturity: 'UNSUPPORTED', platforms: ['native'], extensions: ['.zig'], note: 'Detected and counted; no rules yet.' },
  { id: 'nim', label: 'Nim', maturity: 'UNSUPPORTED', platforms: ['backend'], extensions: ['.nim'], note: 'Detected and counted; no rules yet.' },
  { id: 'v', label: 'V', maturity: 'UNSUPPORTED', platforms: ['native'], extensions: ['.v'], note: 'Detected and counted; no rules yet.' },
];

/** True when files of this family are analyzed (rule engines run). */
export function isAnalyzedMaturity(maturity: SastMaturity): boolean {
  return maturity === 'PARTIAL' || maturity === 'CONFIG_ANALYSIS' || maturity === 'FULL';
}

export interface SastLanguageDetection {
  readonly family: string;
  readonly maturity: SastMaturity;
  /** How the family was determined (tests/docs; deterministic). */
  readonly via: 'extension' | 'filename' | 'shebang' | 'content-tiebreak';
}

const extensionIndex = new Map<string, SastLanguageFamily>();
const filenameIndex = new Map<string, SastLanguageFamily>();
const shebangIndex = new Map<string, SastLanguageFamily>();
for (const family of SAST_LANGUAGE_CATALOG) {
  for (const extension of family.extensions ?? []) {
    extensionIndex.set(extension.toLowerCase(), family);
  }
  for (const filename of family.filenames ?? []) {
    filenameIndex.set(filename.toLowerCase(), family);
  }
  for (const interpreter of family.shebangs ?? []) {
    shebangIndex.set(interpreter.toLowerCase(), family);
  }
}

const OBJC_MARKERS = /#import|@interface|@implementation|NSLog|UIApplication|UIColor/;
const MATLAB_MARKERS = /%[^\n]*|^\s*function\s+\w+/;

/**
 * Deterministic language detection for one snapshot file.
 *
 * Order: exact filename → extension → shebang (first line of
 * `contentSample`) → content tie-breaks (`.m` Objective-C vs MATLAB;
 * YAML vs GitHub Actions workflow). Returns `undefined` for unknown
 * files (they are skipped and counted, never guessed at).
 */
export function detectLanguageFamily(path: string, contentSample?: string): SastLanguageDetection | undefined {
  const lowerPath = path.toLowerCase();
  const basename = lowerPath.split('/').pop() ?? lowerPath;
  const dot = basename.lastIndexOf('.');
  const extension = dot > 0 ? basename.slice(dot) : '';

  // 1. Exact filename families (Dockerfile, AndroidManifest.xml, Gemfile…).
  const byFilename = filenameIndex.get(basename);
  if (byFilename !== undefined) {
    return { family: byFilename.id, maturity: byFilename.maturity, via: 'filename' };
  }

  // 2. Extension families — with the two documented content tie-breaks.
  if (extension === '.m') {
    // Objective-C vs MATLAB share `.m`: deterministic content markers
    // decide; the default is Objective-C (the mobile-platform reading).
    const objc = contentSample !== undefined && OBJC_MARKERS.test(contentSample);
    const matlab = !objc && contentSample !== undefined && MATLAB_MARKERS.test(contentSample);
    if (objc) return { family: 'objc', maturity: 'PARTIAL', via: 'content-tiebreak' };
    if (matlab) return { family: 'matlab', maturity: 'UNSUPPORTED', via: 'content-tiebreak' };
    const objcFamily = extensionIndex.get('.m');
    return objcFamily === undefined
      ? undefined
      : { family: objcFamily.id, maturity: objcFamily.maturity, via: 'extension' };
  }
  const byExtension = extensionIndex.get(extension);
  if (byExtension !== undefined) {
    if (byExtension.id === 'yaml' && contentSample !== undefined) {
      // GitHub Actions workflows cannot be detected by path (snapshot
      // paths never contain dotfile segments): `runs-on:` plus a
      // `jobs:`/`on:` marker is the deterministic workflow shape.
      if (/^\s*runs-on:/m.test(contentSample) && (/^\s*jobs:/m.test(contentSample) || /^\s*on:/m.test(contentSample))) {
        const gha = extensionIndex.get('.yml');
        const ghaFamily = SAST_LANGUAGE_CATALOG.find((family) => family.id === 'github-actions');
        void gha;
        if (ghaFamily !== undefined) {
          return { family: ghaFamily.id, maturity: ghaFamily.maturity, via: 'content-tiebreak' };
        }
      }
    }
    return { family: byExtension.id, maturity: byExtension.maturity, via: 'extension' };
  }

  // 3. Shebang (extension-less executable scripts).
  if (contentSample !== undefined) {
    const shebang = contentSample.match(/^#!\s*(?:\/[^\s]*\/)?(?:env\s+)?([^\s]+)/);
    if (shebang !== null) {
      const interpreter = (shebang[1] ?? '').toLowerCase();
      const byShebang = shebangIndex.get(interpreter);
      if (byShebang !== undefined) {
        return { family: byShebang.id, maturity: byShebang.maturity, via: 'shebang' };
      }
    }
  }
  return undefined;
}

/**
 * Deterministic framework detection over the snapshot's manifest/build
 * files (application logic, not a dataset). Returns unique labels in
 * catalog order for stable output.
 */
const FRAMEWORK_MARKERS: ReadonlyArray<{
  readonly file: (path: string) => boolean;
  readonly test: RegExp;
  readonly label: string;
}> = [
  { file: (p) => p.toLowerCase().endsWith('package.json'), test: /"(?:dependencies|devDependencies)"\s*:\s*\{[^}]*"(?:react|react-dom)"/s, label: 'React' },
  { file: (p) => p.toLowerCase().endsWith('package.json'), test: /"(?:dependencies|devDependencies)"\s*:\s*\{[^}]*"next"/s, label: 'Next.js' },
  { file: (p) => p.toLowerCase().endsWith('package.json'), test: /"(?:dependencies|devDependencies)"\s*:\s*\{[^}]*"@?angular\/core"/s, label: 'Angular' },
  { file: (p) => p.toLowerCase().endsWith('package.json'), test: /"(?:dependencies|devDependencies)"\s*:\s*\{[^}]*"vue"/s, label: 'Vue' },
  { file: (p) => p.toLowerCase().endsWith('package.json'), test: /"(?:dependencies|devDependencies)"\s*:\s*\{[^}]*"(?:express)"/s, label: 'Express' },
  { file: (p) => p.toLowerCase().endsWith('package.json'), test: /"(?:dependencies|devDependencies)"\s*:\s*\{[^}]*"fastify"/s, label: 'Fastify' },
  { file: (p) => p.toLowerCase().endsWith('package.json'), test: /"(?:dependencies|devDependencies)"\s*:\s*\{[^}]*"@nestjs\/core"/s, label: 'NestJS' },
  { file: (p) => p.toLowerCase().endsWith('package.json'), test: /"(?:dependencies|devDependencies)"\s*:\s*\{[^}]*"koa"/s, label: 'Koa' },
  { file: (p) => p.toLowerCase().endsWith('package.json'), test: /"(?:dependencies|devDependencies)"\s*:\s*\{[^}]*"electron"/s, label: 'Electron' },
  { file: (p) => p.toLowerCase().endsWith('package.json'), test: /"(?:dependencies|devDependencies)"\s*:\s*\{[^}]*"react-native"/s, label: 'React Native' },
  { file: (p) => p.toLowerCase().endsWith('requirements.txt'), test: /^\s*django\b/im, label: 'Django' },
  { file: (p) => p.toLowerCase().endsWith('requirements.txt'), test: /^\s*flask\b/im, label: 'Flask' },
  { file: (p) => p.toLowerCase().endsWith('requirements.txt'), test: /^\s*fastapi\b/im, label: 'FastAPI' },
  { file: (p) => p.toLowerCase().endsWith('requirements.txt'), test: /^\s*tornado\b/im, label: 'Tornado' },
  { file: (p) => p.toLowerCase().endsWith('requirements.txt'), test: /^\s*aiohttp\b/im, label: 'aiohttp' },
  { file: (p) => p.toLowerCase().endsWith('pom.xml'), test: /spring-boot-starter|<artifactId>spring/, label: 'Spring Boot' },
  { file: (p) => p.toLowerCase().endsWith('build.gradle') || p.toLowerCase().endsWith('build.gradle.kts'), test: /org\.springframework\.boot/, label: 'Spring Boot' },
  { file: (p) => p.toLowerCase().endsWith('build.gradle') || p.toLowerCase().endsWith('build.gradle.kts'), test: /androidx|com\.android\.(?:application|library)/, label: 'Android' },
  { file: (p) => p.toLowerCase().endsWith('composer.json'), test: /"laravel\/framework"/, label: 'Laravel' },
  { file: (p) => p.toLowerCase().endsWith('composer.json'), test: /"symfony\/http-foundation"/, label: 'Symfony' },
  { file: (p) => p.toLowerCase().endsWith('go.mod'), test: /github\.com\/gin-gonic\/gin/, label: 'Gin' },
  { file: (p) => p.toLowerCase().endsWith('go.mod'), test: /github\.com\/labstack\/echo/, label: 'Echo' },
  { file: (p) => p.toLowerCase().endsWith('go.mod'), test: /github\.com\/gofiber\/fiber/, label: 'Fiber' },
  { file: (p) => p.toLowerCase().endsWith('gemfile'), test: /^\s*gem\s+['"]rails['"]/im, label: 'Rails' },
  { file: (p) => p.toLowerCase().endsWith('.csproj'), test: /Microsoft\.NET\.Sdk\.Web/, label: 'ASP.NET Core' },
  { file: (p) => p.toLowerCase().endsWith('pubspec.yaml'), test: /^\s*flutter:/m, label: 'Flutter' },
];

/**
 * Framework detection over the whole snapshot: manifest/build files are
 * inspected with fixed, hand-written markers. Deterministic, unique,
 * catalog-ordered output — or an empty list (never a guess).
 */
export function detectFrameworks(files: ReadonlyArray<{ path: string; content: string }>): string[] {
  const found = new Set<string>();
  for (const file of files) {
    for (const marker of FRAMEWORK_MARKERS) {
      if (marker.file(file.path) && marker.test.test(file.content)) {
        found.add(marker.label);
      }
    }
  }
  return [...found].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/** Derived catalog counts — calculated, never hand-written. */
export interface SastMaturityCounts {
  readonly total: number;
  readonly full: number;
  readonly partial: number;
  readonly syntaxOnly: number;
  readonly configAnalysis: number;
  readonly unsupported: number;
}

export function sastMaturityCounts(): SastMaturityCounts {
  let full = 0;
  let partial = 0;
  let syntaxOnly = 0;
  let configAnalysis = 0;
  let unsupported = 0;
  for (const family of SAST_LANGUAGE_CATALOG) {
    if (family.maturity === 'FULL') full += 1;
    else if (family.maturity === 'PARTIAL') partial += 1;
    else if (family.maturity === 'SYNTAX_ONLY') syntaxOnly += 1;
    else if (family.maturity === 'CONFIG_ANALYSIS') configAnalysis += 1;
    else unsupported += 1;
  }
  return { total: SAST_LANGUAGE_CATALOG.length, full, partial, syntaxOnly, configAnalysis, unsupported };
}

export type { FindingSeverity };


/**
 * Pump 16: families with a bounded shallow-AST/dataflow profile.
 * This does NOT change `maturity` — a BOUNDED AST is still PARTIAL, never
 * FULL. It only says an extra structural pass is available for the family.
 */
export function supportsBoundedAst(family: string): boolean {
  return AST_SUPPORTED_FAMILIES.includes(family);
}
