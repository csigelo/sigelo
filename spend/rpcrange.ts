/**
 * The monero-wallet-rpc versions the keeper accepts (MONERO.md §4.1 "The wallet-rpc it
 * accepts"). Its own module so `sigelo-spend doctor` ships it; canary.ts, which is not in the
 * package, re-exports it and documents why the range is what it is.
 *
 * wallet-rpc's `get_version`: `version` = major << 16 | minor. PINNED_RPC is the one version
 * every check, the whole spend/ suite and the stock-wallet oracle actually RAN against: 1.30 =
 * v0.18.5.0. The rest of RPC_RANGE is accepted on a SOURCE DIFF only (canary.ts).
 */
export const PINNED_RPC = { major: 1, minor: 30 };
export const RPC_RANGE = { major: 1, minMinor: 30, maxMinor: 33 };
/** The version rule: major 1 and 30 <= minor <= 33 (RPC_RANGE). */
export const rpcVersionOk = (major: number, minor: number): boolean =>
  major === RPC_RANGE.major && minor >= RPC_RANGE.minMinor && minor <= RPC_RANGE.maxMinor;
