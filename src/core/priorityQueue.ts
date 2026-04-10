/**
 * Priority Queue for tool execution
 * Based on task importance and resource requirements
 */

export interface ToolTask {
  toolName: string;
  input: Record<string, unknown>;
  priority: number; // 0-10, higher = more important
  resourceDemand: number; // 0-10, higher = more resources needed
  id: string;
  createdAt: number;
}

export class PriorityQueue {
  private queue: ToolTask[] = [];

  /**
   * Add a task to the queue
   */
  add(task: Omit<ToolTask, 'id' | 'createdAt'>): string {
    const id = `task_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const newTask: ToolTask = {
      ...task,
      id,
      createdAt: Date.now()
    };
    
    this.queue.push(newTask);
    this.sort();
    return id;
  }

  /**
   * Remove and return the highest priority task
   */
  next(): ToolTask | undefined {
    if (this.isEmpty()) return undefined;
    return this.queue.shift();
  }

  /**
   * Get the next task without removing it
   */
  peek(): ToolTask | undefined {
    if (this.isEmpty()) return undefined;
    return this.queue[0];
  }

  /**
   * Remove a task by id
   */
  remove(id: string): boolean {
    const initialLength = this.queue.length;
    this.queue = this.queue.filter(task => task.id !== id);
    return this.queue.length < initialLength;
  }

  /**
   * Check if the queue is empty
   */
  isEmpty(): boolean {
    return this.queue.length === 0;
  }

  /**
   * Get the number of tasks in the queue
   */
  size(): number {
    return this.queue.length;
  }

  /**
   * Sort tasks by priority
   * Priority calculation: priority * 0.7 + (10 - resourceDemand) * 0.2 + (age factor) * 0.1
   */
  private sort(): void {
    const now = Date.now();
    this.queue.sort((a, b) => {
      const ageA = (now - a.createdAt) / 60000; // Age in minutes
      const ageB = (now - b.createdAt) / 60000;
      
      const scoreA = a.priority * 0.7 + (10 - a.resourceDemand) * 0.2 + Math.min(ageA, 10) * 0.1;
      const scoreB = b.priority * 0.7 + (10 - b.resourceDemand) * 0.2 + Math.min(ageB, 10) * 0.1;
      
      return scoreB - scoreA; // Descending order
    });
  }

  /**
   * Clear the queue
   */
  clear(): void {
    this.queue = [];
  }

  /**
   * Get all tasks
   */
  getAll(): ToolTask[] {
    return [...this.queue];
  }
}
