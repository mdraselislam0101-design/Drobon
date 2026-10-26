/**
 * BOUNDED AST ENGINE — language profiles (Pump 16, MAIN-APP ONLY).
 *
 * These profiles are DATA: generic API surface names (sources, sinks,
 * sanitizers) and syntax hints. They contain NO vulnerability-database
 * bytes and NO CVE/NVD/GHSA/OSV/KEV/EPSS content — the dataset lock holds.
 * Adding a new language is a profile entry, not a new parser.
 *
 * The parser is deliberately SHALLOW: a bounded tokenizer plus a
 * structural statement/call/assignment tree. It is NOT a full ECMAScript,
 * PHP or Python grammar. Honest limitations are documented in
 * docs/DEEP_SAST.md and asserted by tests.
 */

export type AstFlowKind = 'command' | 'sql' | 'html' | 'code';

export interface AstLanguageProfile {
  readonly family: string;
  readonly lineComments: readonly string[];
  readonly blockComments: ReadonlyArray<{ open: string; close: string }>;
  readonly quotes: readonly string[];
  readonly tripleQuotes?: readonly string[];
  /** Operators that join identifier chains: `.`, `->`, `::`. */
  readonly memberOperators: readonly string[];
  /** Assignment operators (plain `=` plus language-specific ones). */
  readonly assignmentOperators: readonly string[];
  /** True for indentation-based languages (Python/Ruby) — split on newlines. */
  readonly newlineStatements: boolean;
  /** Identifier CHAIN prefixes that introduce untrusted data. */
  readonly sources: readonly string[];
  /** Bare callee names that are sources (e.g. `input`, `getParameter`). */
  readonly sourceCalls: readonly string[];
  /** Callee/chain names that neutralize taint (explicit allowlist). */
  readonly sanitizers: readonly string[];
  /** Callee/chain names per flow class. */
  readonly sinks: Readonly<Record<AstFlowKind, readonly string[]>>;
  /** Markers inside a string token that mean a query is parameterized. */
  readonly parameterizedSql: readonly string[];
}

const C_BLOCK = [{ open: '/*', close: '*/' }] as const;

const SOURCE_CALLS = [
  'input', 'getParameter', 'getHeader', 'getStringExtra', 'getExtras',
  'FormValue', 'FormFile', 'ReadLine', 'readline', 'question', 'prompt',
  'parse', 'fetch',
] as const;

const SANITIZERS = [
  'encodeURIComponent', 'encodeURI', 'escapeHtml', 'escapeHTML', 'sanitizeHtml',
  'DOMPurify.sanitize', 'parseInt', 'parseFloat', 'Number', 'String', 'Boolean',
  'int', 'intval', 'floatval', 'html.escape', 'bleach.clean', 'markupsafe.escape',
  'shlex.quote', 'pipes.quote', 'escapeshellarg', 'escapeshellcmd', 'preg_quote',
  'Integer.parseInt', 'Integer.valueOf', 'Long.valueOf', 'setInt', 'setLong', 'setString',
  'strconv.Atoi', 'url.QueryEscape', 'html.EscapeString', 'HttpUtility.HtmlEncode',
  'Uri.EscapeDataString', 'Shellwords.escape', 'Shellwords.shellescape', 'CGI.escapeHTML',
  'prepare', 'bindParam', 'bindValue', 'escape', 'quote', 'textContent',
] as const;

const COMMAND_SINKS = [
  'exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync',
  'os.system', 'os.popen', 'subprocess.run', 'subprocess.call',
  'subprocess.Popen', 'subprocess.check_output', 'subprocess.check_call',
  'shell_exec', 'passthru', 'proc_open', 'system',
  'Runtime.getRuntime', 'Process.Start', 'ProcessBuilder',
  'exec.Command', 'Kernel.system', 'Open3.capture3', 'IO.popen',
] as const;

const SQL_SINKS = [
  'query', 'execute', 'executemany', 'executeQuery', 'executeUpdate', 'raw',
  'mysqli_query', 'db.query', 'client.query', 'pool.query', 'knex.raw',
  'sequelize.query', 'prisma.$queryRaw', 'Query', 'Exec', 'SqlCommand',
  'ExecuteReader', 'ExecuteNonQuery', 'ExecuteScalar',
] as const;

const CODE_SINKS = [
  'eval', 'Function', 'vm.runInNewContext', 'runInNewContext', 'runInContext',
  'setTimeout', 'setInterval', 'unserialize', 'pickle.loads', 'yaml.load',
  'compile', 'render_template_string', 'Markup',
] as const;

const HTML_SINKS = [
  'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
  'dangerouslySetInnerHTML', 'insertAdjacentHTML', 'html', 'append',
  'render_template_string', 'Markup', 'Response.Write', 'echo', 'print',
] as const;

const PARAMETERIZED_SQL = ['?', '%s', '$1', '$2', ':name', ':id', '@p1'] as const;

function cLike(family: string, overrides: Partial<AstLanguageProfile> = {}): AstLanguageProfile {
  return {
    family,
    lineComments: ['//'],
    blockComments: C_BLOCK,
    quotes: ["'", '"', '`'],
    memberOperators: ['.', '?.'],
    assignmentOperators: ['=', '+=', '.='],
    newlineStatements: false,
    sources: [],
    sourceCalls: SOURCE_CALLS,
    sanitizers: SANITIZERS,
    sinks: { command: COMMAND_SINKS, sql: SQL_SINKS, html: HTML_SINKS, code: CODE_SINKS },
    parameterizedSql: PARAMETERIZED_SQL,
    ...overrides,
  };
}

const JS_SOURCES = [
  'req.body', 'req.query', 'req.params', 'req.headers', 'req.cookies', 'req.files',
  'request.body', 'request.query', 'request.params', 'request.headers',
  'ctx.request.body', 'ctx.query', 'ctx.params', 'process.argv',
  'location.search', 'location.hash', 'window.location', 'document.location',
  'document.cookie', 'localStorage', 'sessionStorage', 'event.data', 'msg.data',
  'payload', 'userInput', 'rawInput', 'argv',
] as const;

const PY_SOURCES = [
  'request.args', 'request.form', 'request.values', 'request.json', 'request.data',
  'request.cookies', 'request.headers', 'sys.argv', 'flask.request',
] as const;

const PHP_SOURCES = [
  '$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_SERVER', '$_FILES',
  'php://input', 'filter_input',
] as const;

const JVM_SOURCES = [
  'request.getParameter', 'request.getHeader', 'request.getInputStream',
  'intent.getStringExtra', 'intent.getExtras', 'args',
] as const;

const GO_SOURCES = [
  'r.URL.Query', 'r.FormValue', 'r.Header.Get', 'r.Body', 'os.Args',
] as const;

const DOTNET_SOURCES = [
  'Request', 'Request.QueryString', 'Request.Form', 'Request.Cookies',
  'Console.ReadLine', 'args',
] as const;

const RUBY_SOURCES = ['params', 'request.params', 'ARGV', 'env'] as const;

export const AST_LANGUAGE_PROFILES: Readonly<Record<string, AstLanguageProfile>> = Object.freeze({
  javascript: cLike('javascript', { sources: JS_SOURCES }),
  typescript: cLike('typescript', { sources: JS_SOURCES }),
  jsx: cLike('jsx', { sources: JS_SOURCES }),
  tsx: cLike('tsx', { sources: JS_SOURCES }),
  python: cLike('python', {
    lineComments: ['#'],
    blockComments: [],
    quotes: ["'", '"'],
    tripleQuotes: ['"""', "'''"],
    memberOperators: ['.'],
    assignmentOperators: ['=', '+=', ':='],
    newlineStatements: true,
    sources: PY_SOURCES,
  }),
  php: cLike('php', {
    lineComments: ['//', '#'],
    quotes: ["'", '"'],
    memberOperators: ['->', '::', '.'],
    sources: PHP_SOURCES,
  }),
  java: cLike('java', { sources: JVM_SOURCES }),
  kotlin: cLike('kotlin', { sources: JVM_SOURCES }),
  go: cLike('go', { sources: GO_SOURCES }),
  csharp: cLike('csharp', { sources: DOTNET_SOURCES }),
  ruby: cLike('ruby', {
    lineComments: ['#'],
    blockComments: [],
    quotes: ["'", '"'],
    memberOperators: ['.', '::'],
    assignmentOperators: ['=', '+='],
    newlineStatements: true,
    sources: RUBY_SOURCES,
  }),
});

/** Families the bounded AST pass can analyze (kept closed and explicit). */
export const AST_SUPPORTED_FAMILIES: readonly string[] = Object.keys(AST_LANGUAGE_PROFILES);

export function astProfileFor(family: string): AstLanguageProfile | undefined {
  return AST_LANGUAGE_PROFILES[family];
}

/** True when a chain matches a declared name (exact or as a dotted suffix). */
function chainMatches(chain: string, names: readonly string[]): boolean {
  for (const name of names) {
    if (chain === name || chain.endsWith(`.${name}`) || chain.startsWith(`${name}.`) || chain.startsWith(`${name}[`)) {
      return true;
    }
  }
  return false;
}

export function isSourceChain(profile: AstLanguageProfile, chain: string): boolean {
  if (chainMatches(chain, profile.sources)) return true;
  const root = chain.split('.')[0] ?? '';
  return chainMatches(root, profile.sourceCalls);
}

export function isSanitizerChain(profile: AstLanguageProfile, chain: string): boolean {
  return chainMatches(chain, profile.sanitizers);
}

export function sinkKindForChain(profile: AstLanguageProfile, chain: string): AstFlowKind | undefined {
  for (const kind of ['command', 'sql', 'html', 'code'] as const) {
    if (chainMatches(chain, profile.sinks[kind])) return kind;
  }
  return undefined;
}
