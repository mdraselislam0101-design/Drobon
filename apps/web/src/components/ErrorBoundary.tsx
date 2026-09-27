import { Component, type ReactNode } from 'react';
import { ErrorState } from './ErrorState.js';

interface State {
  crashed: boolean;
}

/** Last-resort UI guard: a render crash becomes a message, never a blank page. */
export class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  constructor(props: { children: ReactNode }) {
    super(props);
    this.state = { crashed: false };
  }

  static getDerivedStateFromError(): State {
    return { crashed: true };
  }

  handleReload = (): void => {
    window.location.reload();
  };

  override render(): ReactNode {
    if (this.state.crashed) {
      return (
        <ErrorState
          title="Something went wrong."
          message="The page hit an unexpected error. Reloading usually fixes it."
          onRetry={this.handleReload}
        />
      );
    }
    return this.props.children;
  }
}
