import type { Job } from '@drobon/shared';

/**
 * Minimal queue boundary. Pump 1 ships exactly one implementation
 * ({@link InMemoryJobQueue}); durable queues arrive in a later Pump behind
 * this same interface.
 */
export interface JobQueue {
  enqueue(job: Job): void;
  dequeue(): Job | undefined;
  /** Remove a still-queued job. Returns false when it was already dequeued. */
  cancel(id: string): boolean;
  /** Number of jobs waiting for a worker. */
  readonly pendingCount: number;
}

/**
 * FIFO in-memory queue. Explicitly NOT durable: queued jobs live in process
 * memory only and are lost on restart. Never present this as production
 * infrastructure — it exists so the runner, contracts and tests are real.
 */
export class InMemoryJobQueue implements JobQueue {
  private readonly items = new Map<string, Job>();

  enqueue(job: Job): void {
    if (this.items.has(job.id)) {
      throw new Error(`Job ${job.id} is already queued.`);
    }
    this.items.set(job.id, job);
  }

  dequeue(): Job | undefined {
    for (const [id, job] of this.items) {
      this.items.delete(id);
      return job;
    }
    return undefined;
  }

  cancel(id: string): boolean {
    return this.items.delete(id);
  }

  get pendingCount(): number {
    return this.items.size;
  }

  clear(): void {
    this.items.clear();
  }
}
