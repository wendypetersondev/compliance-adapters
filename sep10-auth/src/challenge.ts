import { Keypair, Networks, WebAuth } from '@stellar/stellar-sdk';

/**
 * Options for customising a SEP-10 challenge transaction.
 * All fields are optional; sensible defaults are applied for local development
 * when omitted.
 */
export interface GenerateChallengeOptions {
  /**
   * The home domain the challenge is issued for (no protocol prefix).
   * Embedded in the challenge transaction's manage-data operation key so the
   * client wallet can identify which server issued it.
   * Defaults to `"localhost:3000"`.
   */
  homeDomain?: string;

  /**
   * The domain that hosts the SEP-10 web-auth endpoint.
   * Defaults to `homeDomain` when not provided, which is correct unless your
   * auth server lives on a dedicated subdomain (e.g. `auth.example.com`).
   */
  webAuthDomain?: string;

  /**
   * Stellar network passphrase used to hash and sign the challenge transaction.
   * Must match the network the client wallet is connected to.
   * Defaults to `Networks.TESTNET`.
   */
  networkPassphrase?: string;

  /**
   * How long (in seconds) the challenge is valid before it expires.
   * The client must sign and return it within this window.
   * Defaults to `300` (five minutes).
   */
  timeoutSeconds?: number;

  /**
   * Optional memo to attach to the challenge transaction.
   * Required by some custodial wallets that share a single Stellar account
   * across many users and use the memo to identify the sub-account.
   * Pass `null` or omit to include no memo.
   */
  memo?: string | null;
}

/**
 * The result of a successful {@link generateChallenge} call.
 */
export interface GeneratedChallenge {
  /**
   * Base64-encoded XDR of the unsigned SEP-10 challenge transaction.
   * Send this to the client; the client signs it with their Stellar keypair
   * and returns the signed XDR for verification.
   */
  transactionXDR: string;

  /**
   * The network passphrase that was used to build the transaction.
   * Clients need this to deserialise and sign the XDR with the correct
   * network context.
   */
  networkPassphrase: string;

  /**
   * Wall-clock time after which the challenge transaction is no longer valid.
   * Derived from `Date.now()` plus `timeoutSeconds` at call time.
   */
  expiresAt: Date;
}

const DEFAULT_HOME_DOMAIN = 'localhost:3000';
const DEFAULT_TIMEOUT_SECONDS = 300;

/**
 * Builds a SEP-10 challenge transaction for a Stellar client to sign.
 *
 * The challenge is a Stellar transaction constructed by the server that the
 * client must sign with their secret key to prove ownership of their account.
 * It contains a manage-data operation with a random nonce so it cannot be
 * replayed. The server's keypair (not just the public key) is required here
 * because the challenge itself must be signed by the server before being sent
 * to the client.
 *
 * @param clientAddress - The G... Stellar account ID of the client whose
 *   ownership is being challenged.
 * @param serverKeypair - The server's full {@link Keypair} (public + secret).
 *   Used to sign the challenge transaction so the client can verify it
 *   originated from this server.
 * @param options - Optional overrides for domain, network, timeout, and memo.
 *   See {@link GenerateChallengeOptions} for defaults.
 * @returns A {@link GeneratedChallenge} containing the base64-encoded XDR to
 *   send to the client, the network passphrase it was built with, and the
 *   expiry timestamp.
 */
export function generateChallenge(
  clientAddress: string,
  serverKeypair: Keypair,
  options: GenerateChallengeOptions = {},
): GeneratedChallenge {
  const homeDomain = options.homeDomain ?? DEFAULT_HOME_DOMAIN;
  const webAuthDomain = options.webAuthDomain ?? homeDomain;
  const networkPassphrase = options.networkPassphrase ?? Networks.TESTNET;
  const timeoutSeconds = options.timeoutSeconds ?? DEFAULT_TIMEOUT_SECONDS;

  const transactionXDR = WebAuth.buildChallengeTx(
    serverKeypair,
    clientAddress,
    homeDomain,
    timeoutSeconds,
    networkPassphrase,
    webAuthDomain,
    options.memo ?? null,
  );

  return {
    transactionXDR,
    networkPassphrase,
    expiresAt: new Date(Date.now() + timeoutSeconds * 1000),
  };
}
