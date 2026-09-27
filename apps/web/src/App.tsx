import { BrowserRouter } from 'react-router-dom';
import type { ApiClient } from './api/client.js';
import type { PublicConfig } from './config.js';
import { AppRoutes } from './routes.js';

export function App({
  client,
  config,
}: {
  client: ApiClient;
  config: PublicConfig;
}): React.JSX.Element {
  return (
    <BrowserRouter>
      <AppRoutes client={client} appName={config.appName} appVersion={config.appVersion} />
    </BrowserRouter>
  );
}
