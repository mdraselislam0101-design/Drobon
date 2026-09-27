/** Deployment environments recognized by every component. */
export const ENVIRONMENTS = ['development', 'test', 'production'] as const;

export type EnvironmentName = (typeof ENVIRONMENTS)[number];

/** Log verbosity levels (ascending severity). */
export const LOG_LEVELS = ['debug', 'info', 'warn', 'error'] as const;

export type LogLevel = (typeof LOG_LEVELS)[number];
