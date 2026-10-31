/** Fixture-only marker-flow check for fake shell calls. This is not a shell
 * interpreter or an exploitability proof. null means the bounded check cannot
 * establish whether positional arguments are later interpreted as commands. */
export function classifyShellFlow(calls, marker) {
  let uncertain = false;
  const marked = (value) => typeof value === 'string' && value.includes(marker);
  for (const call of calls) {
    const kind = call.kind ?? call.type;
    if (kind === 'shell' || kind === 'exec') {
      if (typeof call.command !== 'string') uncertain = true;
      else if (marked(call.command)) return true;
      continue;
    }
    if (kind !== 'execFile') { uncertain = true; continue; }
    if (typeof call.program !== 'string' || !Array.isArray(call.args) || call.args.some((value) => typeof value !== 'string')) {
      uncertain = true; continue;
    }
    if (marked(call.program)) return true;
    const option = call.options?.shell;
    if (option !== undefined && typeof option !== 'boolean' && typeof option !== 'string') { uncertain = true; continue; }
    if (option === true || (typeof option === 'string' && option.length > 0)) {
      if (call.args.some(marked)) return true;
      continue;
    }
    const name = call.program.split(/[\\/]/).pop()?.toLowerCase();
    if (!['sh', 'bash', 'cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe'].includes(name)) continue;
    if (!call.args.some(marked)) continue;
    const flag = name === 'cmd' || name === 'cmd.exe' ? '/c' :
      name === 'powershell' || name === 'powershell.exe' || name === 'pwsh' || name === 'pwsh.exe' ? '-command' : '-c';
    const index = call.args.findIndex((arg) => arg.toLowerCase() === flag);
    if (index >= 0 && marked(call.args[index + 1])) return true;
    // Shell scripts can consume positional arguments through eval or other
    // constructs. A fixed command alone cannot prove those arguments safe.
    uncertain = true;
  }
  return uncertain ? null : false;
}
