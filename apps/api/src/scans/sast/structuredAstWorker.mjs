import { parentPort } from 'node:worker_threads';
import { analyzeStructuredAst } from './structuredAst.mjs';

// This entry point is application-owned code, not target code. Uploaded source
// is only passed as data to the parser and is never imported or executed.
if (parentPort === null) throw new Error('AST worker must run in a worker thread.');
const port = parentPort;
port.on('message', async (input) => {
  try {
    if (input.mode === 'supplement') {
      const { analyzeSupplementAst } = await import('./supplementAst.mjs');
      port.postMessage(analyzeSupplementAst(input));
    } else if (input.mode === 'project') {
      const { analyzeProjectAst } = await import('./projectAst.mjs');
      port.postMessage(analyzeProjectAst(input));
    } else if (['python', 'php', 'java'].includes(input.family)) {
      const { analyzePolyglotAst } = await import('./polyglotAst.mjs');
      port.postMessage(analyzePolyglotAst(input));
    } else {
      port.postMessage(analyzeStructuredAst(input));
    }
  } catch {
    // Never send exception messages or untrusted source back to the API.
    port.postMessage({ status: 'ERROR', candidates: [] });
  }
});
