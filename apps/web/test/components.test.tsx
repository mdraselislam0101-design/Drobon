import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, test, vi } from 'vitest';
import { ErrorState } from '../src/components/ErrorState.js';
import { LoadingState } from '../src/components/LoadingState.js';

describe('LoadingState', () => {
  test('announces loading accessibly', () => {
    render(<LoadingState label="Loading things…" />);
    const status = screen.getByRole('status');
    expect(status).toHaveAttribute('aria-busy', 'true');
    expect(status).toHaveTextContent('Loading things…');
  });
});

describe('ErrorState', () => {
  test('shows title, message, request ID and retry', () => {
    const onRetry = vi.fn();
    render(
      <ErrorState
        title="Broken."
        message="Try again later."
        requestId="req-test-1"
        onRetry={onRetry}
      />,
    );
    expect(screen.getByRole('alert')).toHaveTextContent('Broken.');
    expect(screen.getByRole('alert')).toHaveTextContent('Try again later.');
    expect(screen.getByRole('alert')).toHaveTextContent('req-test-1');
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  test('omits the reference line and button when not provided', () => {
    render(<ErrorState title="Broken." message="No retry." />);
    expect(screen.queryByRole('button')).toBeNull();
    expect(screen.getByRole('alert')).not.toHaveTextContent('Reference:');
  });
});
