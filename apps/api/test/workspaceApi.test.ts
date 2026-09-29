import { afterEach, describe, expect, test } from 'vitest';
import { isWorkspaceSecurityOverviewResponse } from '@drobon/shared';
import { readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';

const FIXTURE_PASSWORD = 'pump seventeen workspace fixture';
const SERVERS: TestServer[] = [];
interface Cookies { session: string; device: string }
function cookieHeader(cookies: Cookies): string { return `${cookies.session}; drobon_device=${cookies.device}`; }
async function data<T>(response: Response): Promise<T> { return (await readJson(response) as { data: T }).data; }

afterEach(async () => { await Promise.all(SERVERS.splice(0).map((server) => server.stop())); });

async function createAccount(server: TestServer, email: string, userType: string): Promise<Cookies> {
  const registered = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: FIXTURE_PASSWORD, userType }),
  });
  expect(registered.status).toBe(201);
  const session = sessionCookieFrom(registered);
  const probe = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: session } });
  expect(probe.status).toBe(200);
  const device = probe.headers.getSetCookie().find((value) => value.startsWith('drobon_device='));
  if (device === undefined) throw new Error('Expected the normal device cookie.');
  return { session, device: device.split(';')[0]!.slice('drobon_device='.length) };
}

async function createProject(server: TestServer, cookies: Cookies, name: string): Promise<string> {
  const created = await fetch(`${server.baseUrl}/api/v1/projects`, {
    method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
    body: JSON.stringify({ name }),
  });
  expect(created.status).toBe(201);
  return (await data<{ project: { id: string } }>(created)).project.id;
}

describe('self-scoped workspace security overview', () => {
  test('authenticates every user type and derives scope only from the session', async () => {
    const server = await startTestServer();
    SERVERS.push(server);
    expect((await fetch(`${server.baseUrl}/api/v1/me/security-overview`)).status).toBe(401);

    const privilegeTampering = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'dev-overview@example.test', password: FIXTURE_PASSWORD, userType: 'DEVELOPER', plan: 'PRO', role: 'ADMIN' }),
    });
    expect(privilegeTampering.status).toBe(422);

    const developer = await createAccount(server, 'dev-overview@example.test', 'DEVELOPER');
    const student = await createAccount(server, 'student-overview@example.test', 'STUDENT');
    const pentester = await createAccount(server, 'pentester-overview@example.test', 'PENTESTER');
    const developerProject = await createProject(server, developer, 'Developer-owned fixture');
    const studentProject = await createProject(server, student, 'Student-owned fixture');
    const pentesterProject = await createProject(server, pentester, 'Pentester-owned fixture');
    const configuredTarget = await fetch(`${server.baseUrl}/api/v1/projects/${pentesterProject}/dast-target`, {
      method: 'PUT', headers: { 'content-type': 'application/json', cookie: cookieHeader(pentester) },
      body: JSON.stringify({ targetUrl: 'https://fixture.example.org/' }),
    });
    expect(configuredTarget.status).toBe(200);

    const developerResponse = await fetch(`${server.baseUrl}/api/v1/me/security-overview`, { headers: { cookie: cookieHeader(developer) } });
    const studentResponse = await fetch(`${server.baseUrl}/api/v1/me/security-overview`, { headers: { cookie: cookieHeader(student) } });
    const pentesterResponse = await fetch(`${server.baseUrl}/api/v1/me/security-overview`, { headers: { cookie: cookieHeader(pentester) } });
    expect(developerResponse.status).toBe(200);
    expect(studentResponse.status).toBe(200);
    expect(pentesterResponse.status).toBe(200);
    const developerOverview = await data<unknown>(developerResponse);
    const studentOverview = await data<unknown>(studentResponse);
    const pentesterOverview = await data<{ overview: { projects: { dastTargetsConfigured: number; recent: Array<{ id: string; dastTargetConfigured: boolean }> } } }>(pentesterResponse);
    expect(isWorkspaceSecurityOverviewResponse(developerOverview)).toBe(true);
    expect(isWorkspaceSecurityOverviewResponse(studentOverview)).toBe(true);
    expect(JSON.stringify(developerOverview)).toContain(developerProject);
    expect(JSON.stringify(developerOverview)).not.toContain(studentProject);
    expect(JSON.stringify(studentOverview)).toContain(studentProject);
    expect(JSON.stringify(studentOverview)).not.toContain(developerProject);
    expect(JSON.stringify(developerOverview)).not.toContain(pentesterProject);
    expect(JSON.stringify(pentesterOverview)).toContain(pentesterProject);
    expect(JSON.stringify(pentesterOverview)).not.toContain(developerProject);
    expect(JSON.stringify(pentesterOverview)).not.toContain(studentProject);
    expect(pentesterOverview.overview.projects.dastTargetsConfigured).toBe(1);
    expect(pentesterOverview.overview.projects.recent).toEqual([
      expect.objectContaining({ id: pentesterProject, dastTargetConfigured: true }),
    ]);
    expect(JSON.stringify(developerOverview)).not.toContain('ownerId');

    const invalidTargetCount = JSON.parse(JSON.stringify(pentesterOverview)) as typeof pentesterOverview;
    invalidTargetCount.overview.projects.dastTargetsConfigured = -1;
    expect(isWorkspaceSecurityOverviewResponse(invalidTargetCount)).toBe(false);
    const impossibleTargetCount = JSON.parse(JSON.stringify(pentesterOverview)) as typeof pentesterOverview;
    impossibleTargetCount.overview.projects.dastTargetsConfigured = 2;
    expect(isWorkspaceSecurityOverviewResponse(impossibleTargetCount)).toBe(false);
    const invalidProjectTargetFlag = JSON.parse(JSON.stringify(pentesterOverview)) as { overview: { projects: { recent: Array<{ dastTargetConfigured: unknown }> } } };
    invalidProjectTargetFlag.overview.projects.recent[0]!.dastTargetConfigured = 'authorized';
    expect(isWorkspaceSecurityOverviewResponse(invalidProjectTargetFlag)).toBe(false);

    expect((await fetch(`${server.baseUrl}/api/v1/me/security-overview?accountId=usr_someone-else`, { headers: { cookie: cookieHeader(developer) } })).status).toBe(422);
  });
});
