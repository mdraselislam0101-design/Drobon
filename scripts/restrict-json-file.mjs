#!/usr/bin/env node
/**
 * Opt-in, offline permission-only mitigation for one existing store file.
 * No JSON is read or rewritten. This is not encryption or secret removal.
 * Stop all writers and review ACLs, backup and restore before using it.
 */
import { constants, closeSync, fchmodSync, fstatSync, fsyncSync, openSync, readFileSync, writeFileSync } from 'node:fs';

const usage = 'Usage: node scripts/restrict-json-file.mjs plan <store-file> <new-plan-file> | apply|rollback <store-file> <plan-file> --confirm-owner-only';
const [operation, file, planFile, confirmation, ...extra] = process.argv.slice(2);

class SafeFailure extends Error {}
function fail(message) { throw new SafeFailure(message); }
function regularFile(path, flags) {
  const fd = openSync(path, flags | constants.O_NOFOLLOW | (constants.O_NONBLOCK ?? 0));
  try {
    const info = fstatSync(fd, { bigint: true });
    if (!info.isFile() || info.nlink !== 1n || (info.mode & 0o7000n) !== 0n) fail('Refusing a non-regular, hard-linked, or special-mode file.');
    return { fd, info };
  } catch (error) { closeSync(fd); throw error; }
}
function mode(info) { return Number(info.mode & 0o777n); }
function modeText(value) { return `0${value.toString(8).padStart(3, '0')}`; }
function parsePlan(value) {
  if (typeof value !== 'object' || value === null || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== 'afterMode,beforeMode,device,inode,version' || value.version !== 1 ||
      typeof value.device !== 'string' || !/^\d+$/.test(value.device) ||
      typeof value.inode !== 'string' || !/^\d+$/.test(value.inode) ||
      typeof value.beforeMode !== 'string' || !/^0[0-7]{3}$/.test(value.beforeMode) ||
      typeof value.afterMode !== 'string' || !/^0[0-7]{3}$/.test(value.afterMode)) fail('Invalid permission plan.');
  const before = Number.parseInt(value.beforeMode, 8);
  const after = Number.parseInt(value.afterMode, 8);
  if (after !== (before & 0o700)) fail('Invalid permission plan.');
  return { ...value, before, after };
}

try {
  if (process.platform === 'win32' || typeof constants.O_NOFOLLOW !== 'number') fail('This permission tool requires POSIX O_NOFOLLOW support.');
  if (!file || !planFile || extra.length > 0 || !['plan', 'apply', 'rollback'].includes(operation ?? '') ||
      (operation === 'plan' ? confirmation !== undefined : confirmation !== '--confirm-owner-only')) fail(usage);
  const store = regularFile(file, constants.O_RDONLY);
  try {
    if (operation === 'plan') {
      const before = mode(store.info);
      const plan = { version: 1, device: String(store.info.dev), inode: String(store.info.ino),
        beforeMode: modeText(before), afterMode: modeText(before & 0o700) };
      // O_EXCL refuses an existing file, including the selected store itself.
      const planFd = openSync(planFile, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      try { writeFileSync(planFd, `${JSON.stringify(plan, null, 2)}\n`, 'utf8'); fsyncSync(planFd); }
      finally { closeSync(planFd); }
      console.log(JSON.stringify({ operation, beforeMode: plan.beforeMode, afterMode: plan.afterMode, changeRequired: before !== (before & 0o700) }));
    } else {
      const saved = regularFile(planFile, constants.O_RDONLY);
      let plan;
      try {
        if (saved.info.size > 4096n || (mode(saved.info) & 0o077) !== 0 ||
            (saved.info.dev === store.info.dev && saved.info.ino === store.info.ino)) fail('Unsafe permission plan.');
        plan = parsePlan(JSON.parse(readFileSync(saved.fd, 'utf8')));
      } finally { closeSync(saved.fd); }
      const currentInfo = fstatSync(store.fd, { bigint: true });
      if (!currentInfo.isFile() || currentInfo.nlink !== 1n || (currentInfo.mode & 0o7000n) !== 0n ||
          String(currentInfo.dev) !== plan.device || String(currentInfo.ino) !== plan.inode) fail('The store file no longer matches the plan.');
      const from = operation === 'apply' ? plan.before : plan.after;
      const to = operation === 'apply' ? plan.after : plan.before;
      const current = mode(currentInfo);
      if (current !== from && current !== to) fail('The store permissions no longer match the plan.');
      if (current !== to) fchmodSync(store.fd, to);
      const actual = mode(fstatSync(store.fd, { bigint: true }));
      if (actual !== to) fail('Could not verify the resulting permission bits.');
      console.log(JSON.stringify({ operation, changed: current !== to, beforeMode: modeText(current), afterMode: modeText(actual) }));
    }
  } finally { closeSync(store.fd); }
} catch (error) {
  // Do not echo supplied filenames or filesystem errors, which can be sensitive.
  const safe = error instanceof SafeFailure ? error.message : 'Permission operation failed; no filename is printed.';
  console.error(safe);
  process.exitCode = 1;
}
