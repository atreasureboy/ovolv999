// Minimal memory stub — full memory system was removed during cleanup

export function getMemoryDir(_cwd: string): string {
  return ''
}

export function buildMemorySystemSection(_dir: string): string {
  return ''
}

export function getMemoryStats(_dir: string): { hasIndex: boolean; entryCount: number } {
  return { hasIndex: false, entryCount: 0 }
}
