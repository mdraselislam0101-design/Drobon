// Copy runtime-only assets into the API build so standalone build artifacts
// contain the same font used by the development server. No data is fetched.
import { cp, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const source = fileURLToPath(new URL('../apps/api/src/assets/', import.meta.url));
const destination = fileURLToPath(new URL('../apps/api/dist/assets/', import.meta.url));
await mkdir(destination, { recursive: true });
await cp(source, destination, { recursive: true });
