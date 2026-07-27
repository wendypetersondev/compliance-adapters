import { Networks, WebAuth } from '@stellar/stellar-sdk';

/**
 * Options required to verify a client-signed SEP-10 challenge transaction.
 * These values must match what was used when the challenge was originally
 * generated, otherwise signature verification will fail.
 */
export interface VerifyChallengeOptions {
  /**
   * The G... Stellar account ID of the server that issued the challenge.
   * Used to confirm the transaction was signed by the expected server keypair
   * before checking the client's signature.
   */
  serverAccountId: string;

  /**
   * Stellar network passphrase the transaction was built with.
   * Must match the network the client signed on — mixing testnet and mainnet
   * passphrases will cause a hash/signature mismatch.
   * Defaults to `Networks.TESTNET`.
   */
  networkPassphrase?: string;

  /**
   * The home domain(s) accepted as valid issuers of the challenge.
   * Checked against the manage-data operation key embedded in the challenge
   * transaction. Pass a single string or an array when multiple domains are
   * acceptable (e.g. during a domain migration).
   */
  homeDomains: string | string[];

  /**
   * The web-auth domain embedded in the challenge's manage-data operation.
   * Must exactly match the value used during challenge generation.
   */
  webAuthDomain: string;
}

/**
 * The outcome of a {@link verifyChallenge} call.
 * Always check `valid` before using `address`.
 */
export interface VerifyResult {
  /**
   * `true` when the signed transaction passed all SEP-10 validity checks;
   * `false` if any check failed (wrong signer, expired, wrong domain, etc.).
   */
  valid: boolean;

  /**
   * The G... Stellar account ID extracted from the verified challenge.
   * Only meaningful when `valid` is `true`; empty string on failure.
   */
  address: string;

  /**
   * Human-readable reason for verification failure.
   * Present only when `valid` is `false`; `undefined` on success.
   */
  error?: string;
}

/**
 * Verifies a client-signed SEP-10 challenge transaction and returns the
 * authenticated Stellar address.
 *
 * Performs two checks in sequence using the Stellar SDK's `WebAuth` helpers:
 * 1. {@link WebAuth.readChallengeTx} — parses the XDR, validates structure,
 *    expiry, home domain, and server signature.
 * 2. {@link WebAuth.verifyChallengeTxSigners} — confirms the client account
 *    has signed the transaction with its own keypair.
 *
 * Any failure in either step is caught and returned as `{ valid: false, error }`,
 * so callers never need to wrap this in a try/catch.
 *
 * @param signedTransactionXDR - Base64-encoded XDR of the challenge transaction
 *   after the client has signed it and returned it to the server.
 * @param options - Server identity and domain values that must match the
 *   original challenge. See {@link VerifyChallengeOptions}.
 * @returns A {@link VerifyResult} where `valid` indicates success. On success,
 *   `address` holds the authenticated G... account ID. On failure, `error`
 *   describes why verification failed.
 */
export function verifyChallenge(
  signedTransactionXDR: string,
  options: VerifyChallengeOptions,
): VerifyResult {
  const networkPassphrase = options.networkPassphrase ?? Networks.TESTNET;

  try {
    const { clientAccountID } = WebAuth.readChallengeTx(
      signedTransactionXDR,
      options.serverAccountId,
      networkPassphrase,
      options.homeDomains,
      options.webAuthDomain,
    );

    WebAuth.verifyChallengeTxSigners(
      signedTransactionXDR,
      options.serverAccountId,
      networkPassphrase,
      [clientAccountID],
      options.homeDomains,
      options.webAuthDomain,
    );

    return { valid: true, address: clientAccountID };
  } catch (error) {
    return {
      valid: false,
      address: '',
      error: error instanceof Error ? error.message : String(error),
    };
  }
}
