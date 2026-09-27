import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { createApiClient } from './api/client.js';
import { App } from './App.js';
import { PublicConfigError, loadPublicConfig } from './config.js';
import './styles.css';

function renderFatal(message: string): void {
  const root = document.getElementById('root');
  if (root === null) {
    return;
  }
  root.innerHTML = '';
  const box = document.createElement('div');
  box.className = 'container fatal';
  box.setAttribute('role', 'alert');
  const heading = document.createElement('h1');
  heading.textContent = 'Configuration error.';
  const detail = document.createElement('p');
  detail.textContent = message;
  box.append(heading, detail);
  root.append(box);
}

function boot(): void {
  let config;
  try {
    config = loadPublicConfig(import.meta.env);
  } catch (error) {
    renderFatal(
      error instanceof PublicConfigError
        ? error.message
        : 'Invalid public configuration. The app cannot start.',
    );
    return;
  }
  const client = createApiClient({ baseUrl: config.apiBaseUrl });
  const rootElement = document.getElementById('root');
  if (rootElement === null) {
    renderFatal('Missing application root element.');
    return;
  }
  createRoot(rootElement).render(
    <StrictMode>
      <App client={client} config={config} />
    </StrictMode>,
  );
}

boot();
