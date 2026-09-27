import { describe, expect, test } from 'vitest';
import { createJob } from '@drobon/shared';
import { InMemoryJobQueue } from '../src/queue.js';

const makeJob = (id: string) =>
  createJob('test.echo', { id }, { generateId: () => id });

describe('InMemoryJobQueue', () => {
  test('is FIFO', () => {
    const queue = new InMemoryJobQueue();
    queue.enqueue(makeJob('a'));
    queue.enqueue(makeJob('b'));
    queue.enqueue(makeJob('c'));
    expect(queue.pendingCount).toBe(3);
    expect(queue.dequeue()?.id).toBe('a');
    expect(queue.dequeue()?.id).toBe('b');
    expect(queue.dequeue()?.id).toBe('c');
    expect(queue.dequeue()).toBeUndefined();
    expect(queue.pendingCount).toBe(0);
  });

  test('cancel removes a waiting job and reports accurately', () => {
    const queue = new InMemoryJobQueue();
    queue.enqueue(makeJob('a'));
    expect(queue.cancel('a')).toBe(true);
    expect(queue.cancel('a')).toBe(false);
    expect(queue.cancel('missing')).toBe(false);
    expect(queue.dequeue()).toBeUndefined();
  });

  test('rejects duplicate IDs while queued', () => {
    const queue = new InMemoryJobQueue();
    queue.enqueue(makeJob('a'));
    expect(() => queue.enqueue(makeJob('a'))).toThrowError();
  });

  test('clear empties the queue', () => {
    const queue = new InMemoryJobQueue();
    queue.enqueue(makeJob('a'));
    queue.clear();
    expect(queue.pendingCount).toBe(0);
    expect(queue.dequeue()).toBeUndefined();
  });
});
