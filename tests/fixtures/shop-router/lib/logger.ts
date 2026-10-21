export const logger = {
  error(message: string, error: unknown): void {
    console.error(message, error);
  },
  warn(message: string, detail: unknown): void {
    console.warn(message, detail);
  },
};
