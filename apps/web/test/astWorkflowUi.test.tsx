// @vitest-environment jsdom
import { render, screen } from '@testing-library/react';
import { describe, expect, test } from 'vitest';
import type { UserType } from '@drobon/shared';
import { AstWorkflowGuide } from '../src/components/AstWorkflowGuide.js';

describe('AST guidance by user classification', () => {
  const cases: Array<[UserType | null, string]> = [
    ['DEVELOPER', 'Prioritize SAST source flows'],
    ['STUDENT', 'Learn by comparing'],
    ['SECURITY_PROFESSIONAL', 'Review parser gaps'],
    ['PENTESTER', 'Obtain written permission'],
    [null, 'Choose a user type'],
  ];
  test.each(cases)('%s sees tailored presentation only', (userType, expected) => {
    render(<AstWorkflowGuide userType={userType} />);
    const guidance = screen.getByTestId('ast-workflow-guide');
    expect(guidance).toHaveTextContent(expected);
    expect(guidance).toHaveTextContent('User type changes guidance only');
    expect(guidance).toHaveTextContent('not engine permissions');
    expect(guidance).toHaveTextContent('never executes the analyzed code');
  });
});
