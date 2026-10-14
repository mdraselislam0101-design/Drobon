import type { StudentLessonPublic, StudentPracticeFile, StudentQuizQuestionPublic } from '@drobon/shared';

/**
 * Student lesson catalog (Phase 22 Pump 2). INTERNALLY AUTHORED educational
 * content — no CVE/NVD/GHSA/OSV/KEV/EPSS data, no exploit material, no
 * external feed. Every practice exercise is a small SYNTHETIC source file
 * that the learner imports into their OWN project and analyses with the
 * existing deterministic SAST engine; DROBON never executes learner code.
 * Quiz answers stay server-side: the public projection strips them.
 */

interface StudentQuizQuestionInternal extends StudentQuizQuestionPublic {
  answerIndex: number;
  explanation: string;
}

export interface StudentLessonInternal {
  id: string;
  title: string;
  summary: string;
  concept: string;
  objectives: string[];
  practice: {
    instruction: string;
    targetRuleId: string;
    starterFiles: StudentPracticeFile[];
    fixInstruction: string;
    fixedFiles: StudentPracticeFile[];
  };
  quiz: StudentQuizQuestionInternal[];
}

function file(path: string, content: string): StudentPracticeFile {
  return { path, content };
}

const LESSONS: StudentLessonInternal[] = [
  {
    id: 'lsn_code_injection_eval',
    title: 'Dynamic code evaluation: why eval on built strings is dangerous',
    summary: 'Learn what code injection is, recognise the eval-on-concatenation shape, and fix it with data structures.',
    concept:
      'eval() and new Function() execute a string as JavaScript. When part of that string is built from input ' +
      '(concatenation or template interpolation), the input becomes code. An attacker who controls the input ' +
      'controls the program: data and code blur into one channel. The safe pattern is to never build code from ' +
      'values. Almost every eval-on-a-built-string can be replaced with a lookup table, an explicit branch, or ' +
      'a real parser for the exact data format. This lesson pairs with the DROBON SAST rule DG-SAST-002, which ' +
      'flags the lexical shape eval(<built string>) / new Function(<built string>). The rule is line-based and ' +
      'conservative: eval(variable) pass-through is not detected, so a clean scan is evidence about this shape, ' +
      'not a general safety proof.',
    objectives: [
      'Explain why mixing input into executed code is code injection.',
      'Recognise the eval/new-Function-on-a-built-string pattern in review.',
      'Replace dynamic evaluation with data structures or explicit parsing.',
    ],
    practice: {
      instruction:
        'Import the starter file into one of your OWN projects, run a SAST scan, and find rule DG-SAST-002. ' +
        'Read the finding, then apply the fix (replace eval with a lookup map), upload the fixed file, and run ' +
        'SAST again to verify the finding is no longer observed.',
      targetRuleId: 'DG-SAST-002',
      starterFiles: [
        file('src/calculator.js', [
          '// SYNTHETIC learning fixture (not production code).',
          'const operations = { add: 1, sub: 2, mul: 3 };',
          '',
          'function compute(kind, a, b) {',
          '  return eval("a + b - " + operations[kind]);',
          '}',
          '',
          'module.exports = { compute };',
          '',
        ].join('\n')),
      ],
      fixInstruction:
        'Replace the eval with normal JavaScript: use the map value directly (for example const offset = operations[kind]; ' +
        'if (offset === undefined) throw new Error("unknown operation"); return a + b - offset;). Data, not code.',
      fixedFiles: [
        file('src/calculator.js', [
          '// Fixed: no dynamic evaluation, the operation is plain data.',
          'const operations = { add: 1, sub: 2, mul: 3 };',
          '',
          'function compute(kind, a, b) {',
          '  const offset = operations[kind];',
          '  if (offset === undefined) throw new Error("unknown operation");',
          '  return a + b - offset;',
          '}',
          '',
          'module.exports = { compute };',
          '',
        ].join('\n')),
      ],
    },
    quiz: [
      {
        prompt: 'Why is eval("a + b - " + value) risky when value comes from a request?',
        options: [
          'eval is slow and wastes CPU cycles.',
          'The concatenated value becomes executable code, so input can inject behaviour.',
          'eval only fails on very long strings.',
        ],
        answerIndex: 1,
        explanation: 'Concatenated input is parsed as JavaScript. An attacker controlling the string controls what runs — that is code injection.',
      },
      {
        prompt: 'What is the safest replacement for building code from values?',
        options: [
          'Escape the input before eval.',
          'Wrap eval in try/catch.',
          'Use data structures, explicit branches, or a real parser — never build code.',
        ],
        answerIndex: 2,
        explanation: 'Escaping and try/catch do not remove the code/data blur. Lookup tables, branches and format-specific parsers keep data as data.',
      },
      {
        prompt: 'A clean SAST scan means this project can never execute injected code.',
        options: [
          'False — DG-SAST-002 is a lexical, line-based check; pass-through eval is not detected.',
          'True — the scanner proves absence of all injection.',
          'True, but only for JavaScript projects.',
        ],
        answerIndex: 0,
        explanation: 'Pattern-based analysis covers declared shapes only. Honest verification states what was checked, never a general guarantee.',
      },
    ],
  },
  {
    id: 'lsn_command_injection_exec',
    title: 'OS command injection: shells turn arguments into programs',
    summary: 'See how interpolated shell commands execute attacker input, and fix it with argument arrays.',
    concept:
      'exec() and execSync() always invoke a system shell. The whole string is parsed by the shell, so characters ' +
      'like ; | && $() split or chain commands. If any part of the command string is interpolated input, the input ' +
      'is no longer an argument — it is a new command. The structural fix is to avoid the shell: execFile/spawn ' +
      'with an argument array passes each value as exactly one argument and no shell parsing happens. DROBON SAST ' +
      'rule DG-SAST-001 flags exec/execSync called with an interpolated or concatenated command string. It is a ' +
      'lexical v1 rule: exec(variable) pass-through and spawn(..., { shell: true }) are not detected, so treat a ' +
      'clean scan as evidence about this shape only.',
    objectives: [
      'Explain how shell metacharacters turn one command into many.',
      'Recognise interpolated exec/execSync calls in review.',
      'Prefer execFile/spawn with argument arrays over shell strings.',
    ],
    practice: {
      instruction:
        'Import the starter file into one of your OWN projects, run SAST, and find rule DG-SAST-001. Then apply ' +
        'the fix (execFile with an argument array), upload the fixed file, and re-scan to verify.',
      targetRuleId: 'DG-SAST-001',
      starterFiles: [
        file('src/archive.js', [
          '// SYNTHETIC learning fixture (never executed here).',
          '// exec is the shell-running helper from Node\'s child-process builtin; its import line is omitted.',
          '',
          'function makeArchive(folder) {',
          '  exec(`tar czf backup.tgz "${folder}"`);',
          '}',
          '',
          'module.exports = { makeArchive };',
          '',
        ].join('\n')),
      ],
      fixInstruction:
        'Use execFile("tar", ["czf", "backup.tgz", folder]) — the folder stays one argument and no shell parses it.',
      fixedFiles: [
        file('src/archive.js', [
          '// Fixed: no shell — the folder stays a single argument.',
          '// execFile comes from the same child-process builtin (import omitted in this depiction).',
          '',
          'function makeArchive(folder) {',
          '  execFile("tar", ["czf", "backup.tgz", folder]);',
          '}',
          '',
          'module.exports = { makeArchive };',
          '',
        ].join('\n')),
      ],
    },
    quiz: [
      {
        prompt: 'Why does exec(`tar czf out.tgz ${name}`) allow command injection?',
        options: [
          'Template literals are always unsafe in JavaScript.',
          'exec runs the string through a shell, so ; | && inside name start new commands.',
          'tar cannot handle quoted names.',
        ],
        answerIndex: 1,
        explanation: 'exec() always uses a shell. Shell metacharacters in interpolated input split or chain commands — classic CWE-78.',
      },
      {
        prompt: 'Which call passes the folder as data instead of shell syntax?',
        options: [
          'exec("tar czf out.tgz " + folder)',
          'execFile("tar", ["czf", "out.tgz", folder])',
          'exec(`tar czf out.tgz "${name}"`) with escaping',
        ],
        answerIndex: 1,
        explanation: 'execFile/spawn with an argument array skips the shell entirely; each array item is exactly one argument.',
      },
      {
        prompt: 'DROBON reported no DG-SAST-001 findings. What does that honestly mean?',
        options: [
          'No exec/execSync call with an interpolated command string was present in the analysed snapshot.',
          'The project cannot execute any injected command.',
          'All child processes are safe.',
        ],
        answerIndex: 0,
        explanation: 'The scanner asserts the checked pattern is absent from the analysed snapshot — not a guarantee about every code path.',
      },
    ],
  },
  {
    id: 'lsn_xss_dynamic_html',
    title: 'Cross-site scripting basics: markup built from input',
    summary: 'Learn how concatenated HTML becomes an XSS sink, and fix it by rendering text, not markup.',
    concept:
      'Browsers execute scripts found inside HTML. When a page builds markup by concatenating input and hands it ' +
      'to a raw-HTML sink (innerHTML, dangerouslySetInnerHTML, document.write), the input becomes markup, and a ' +
      'fragment like <img src=x onerror=...> becomes running script in your page — stored or reflected XSS ' +
      '(CWE-79). The default fix is to render dynamic values as TEXT: textContent and framework children escape ' +
      'automatically. Only allowlist-based sanitizers justify raw HTML, and only for genuinely trusted markup. ' +
      'DROBON SAST rule DG-SAST-004 flags concatenated/interpolated assignments to raw-HTML sinks; it stays ' +
      'MEDIUM because taintedness cannot be proven without dataflow. A clean scan covers this shape only.',
    objectives: [
      'Describe how input inside markup becomes executable script.',
      'Recognise raw-HTML sinks fed by built strings.',
      'Render dynamic values as text by default; sanitize only with an allowlist.',
    ],
    practice: {
      instruction:
        'Import the starter file into one of your OWN projects, run SAST, and find rule DG-SAST-004. Then apply ' +
        'the fix (textContent instead of innerHTML), upload the fixed file, and re-scan to verify.',
      targetRuleId: 'DG-SAST-004',
      starterFiles: [
        file('src/greeting.js', [
          '// SYNTHETIC learning fixture (not production code).',
          'function greet(el, userName) {',
          '  el.innerHTML = "<p>Hello " + userName + "</p>";',
          '}',
          '',
          'module.exports = { greet };',
          '',
        ].join('\n')),
      ],
      fixInstruction:
        'Create the paragraph element and set its text: const p = document.createElement("p"); p.textContent = "Hello " + userName; el.replaceChildren(p);',
      fixedFiles: [
        file('src/greeting.js', [
          '// Fixed: the name is rendered as text, never as markup.',
          'function greet(el, userName) {',
          '  const p = document.createElement("p");',
          '  p.textContent = "Hello " + userName;',
          '  el.replaceChildren(p);',
          '}',
          '',
          'module.exports = { greet };',
          '',
        ].join('\n')),
      ],
    },
    quiz: [
      {
        prompt: 'A reviewer sees el.innerHTML = "<p>" + input + "</p>". What is the risk?',
        options: [
          'The paragraph renders too slowly.',
          'input can contain markup such as <img onerror=...>, which the browser executes — XSS.',
          'innerHTML ignores all HTML tags.',
        ],
        answerIndex: 1,
        explanation: 'Raw-HTML sinks parse the value as markup. Event-handler attributes inside it run script in your page (CWE-79).',
      },
      {
        prompt: 'What is the default-safe way to show a dynamic value in the DOM?',
        options: [
          'Insert it with innerHTML after removing <script> tags.',
          'Render it as text (textContent or framework children), which escapes by construction.',
          'Base64-encode the value first.',
        ],
        answerIndex: 1,
        explanation: 'Text APIs treat the value as characters, never as markup. Blacklisting <script> misses attribute-based payloads.',
      },
      {
        prompt: 'Why does DROBON rate DG-SAST-004 MEDIUM instead of HIGH?',
        options: [
          'XSS is never a serious vulnerability.',
          'The lexical rule cannot prove the input is attacker-controlled without dataflow analysis.',
          'innerHTML is deprecated.',
        ],
        answerIndex: 1,
        explanation: 'Severity is honest about confidence: the pattern is an XSS sink shape, but exploitability depends on where the value comes from.',
      },
    ],
  },
  {
    id: 'lsn_hardcoded_secrets',
    title: 'Secrets in source code: credentials are not constants',
    summary: 'Learn why hardcoded credentials leak through history and builds, and how the fix is removal plus rotation.',
    concept:
      'Credentials belong to the environment or a secret manager — never to source. A hardcoded key is copied ' +
      'into every clone, build artifact and backup, and removing it later does not un-leak it: history keeps it. ' +
      'That is why remediation is always two steps: move the value out of code AND rotate the exposed value. ' +
      'DROBON flags the shape in two engines: SAST rule DG-SAST-005 (credential-named variable assigned a ' +
      'literal; the evidence is REDACTED so the finding does not re-expose the value) and the dedicated secrets ' +
      'scanner for token-shaped values. DG-SAST-005 is a lexical heuristic on credential-shaped names; it cannot ' +
      'detect obfuscated or composed secrets, and obvious placeholders are excluded so documentation examples do ' +
      'not trigger it.',
    objectives: [
      'Explain why committing credentials is irreversible without rotation.',
      'Recognise credential-named variables assigned literals in review.',
      'Read a redacted secret finding without re-exposing the value.',
    ],
    practice: {
      instruction:
        'Import the starter file into one of your OWN projects, run SAST, and find rule DG-SAST-005 (the evidence ' +
        'will show <redacted>, not the value). Then apply the fix (read from the environment), upload the fixed ' +
        'file, and re-scan to verify.',
      targetRuleId: 'DG-SAST-005',
      starterFiles: [
        file('src/client.js', [
          '// SYNTHETIC learning fixture — the value below is not a real credential.',
          'const config = {',
          '  apiKey: "REDACTED-learning-fixture",',
          '  timeoutMs: 5000,',
          '};',
          '',
          'module.exports = { config };',
          '',
        ].join('\n')),
      ],
      fixInstruction:
        'Read the value from the environment at startup: apiKey: process.env.APP_API_KEY — and rotate any value that was ever committed.',
      fixedFiles: [
        file('src/client.js', [
          '// Fixed: the credential comes from the environment, never from source.',
          'const config = {',
          '  apiKey: process.env.APP_API_KEY,',
          '  timeoutMs: 5000,',
          '};',
          '',
          'module.exports = { config };',
          '',
        ].join('\n')),
      ],
    },
    quiz: [
      {
        prompt: 'A real API key was committed last year and the file was deleted last week. Is the key safe?',
        options: [
          'Yes — deleting the file removes the key from the repository.',
          'No — git history and old clones still contain it; the key must be rotated.',
          'Yes, as long as the repository is private.',
        ],
        answerIndex: 1,
        explanation: 'Removal is not revocation. Anything ever committed must be treated as disclosed and rotated.',
      },
      {
        prompt: 'The DG-SAST-005 finding shows evidence: const apiKey = "<redacted>". Why?',
        options: [
          'The scanner lost the original value.',
          'Redaction keeps the finding readable without re-exposing the secret through APIs or logs.',
          'The value was too long to display.',
        ],
        answerIndex: 1,
        explanation: 'Security tooling must not become a new leak channel; the literal is masked while the location and rule stay actionable.',
      },
      {
        prompt: 'What is the correct remediation for a hardcoded credential?',
        options: [
          'Rename the variable so scanners stop matching.',
          'Move the value to the environment/secret manager AND rotate the exposed value.',
          'Split the value into two strings.',
        ],
        answerIndex: 1,
        explanation: 'Hiding the literal defeats only the scanner. Removal from code plus rotation is the real fix (CWE-798 guidance).',
      },
    ],
  },
];

for (const lesson of LESSONS) {
  for (const question of lesson.quiz) {
    if (!Number.isInteger(question.answerIndex) || question.answerIndex < 0 || question.answerIndex >= question.options.length) {
      throw new Error(`Lesson ${lesson.id} has an out-of-range quiz answer index.`);
    }
  }
}

export const STUDENT_LESSON_CATALOG: readonly StudentLessonInternal[] = LESSONS;

export function findStudentLesson(lessonId: string): StudentLessonInternal | undefined {
  return LESSONS.find((lesson) => lesson.id === lessonId);
}

/** Public projection: quiz answers and explanations are stripped server-side. */
export function studentLessonPublic(lesson: StudentLessonInternal): StudentLessonPublic {
  return {
    id: lesson.id,
    title: lesson.title,
    summary: lesson.summary,
    concept: lesson.concept,
    objectives: lesson.objectives,
    practice: {
      instruction: lesson.practice.instruction,
      targetRuleId: lesson.practice.targetRuleId,
      starterFiles: lesson.practice.starterFiles,
      fixInstruction: lesson.practice.fixInstruction,
    },
    quiz: lesson.quiz.map((question) => ({ prompt: question.prompt, options: question.options })),
  };
}

export function studentLessonCatalogPublic(): StudentLessonPublic[] {
  return LESSONS.map(studentLessonPublic);
}
