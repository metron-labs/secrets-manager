export interface Logger {
    info(message: string, ...meta: unknown[]): void;
    warn(message: string, ...meta: unknown[]): void;
    error(message: string, ...meta: unknown[]): void;
    debug(message: string, ...meta: unknown[]): void;
}

export const defaultLogger: Logger = {
    info: console.log.bind(console, "[INFO]"),
    warn: console.warn.bind(console, "[WARN]"),
    error: console.error.bind(console, "[ERROR]"),
    debug: console.error.bind(console, "[DEBUG]"),
};