import { RequestHandler } from 'express';
import { verifyChallenge, VerifyChallengeOptions } from './verify';

declare global {
  namespace Express {
    interface Request {
      /**
       * The authenticated Stellar account ID (G... address) set by
       * {@link createSep10Middleware} after a valid SEP-10 Bearer token is
       * verified. `undefined` on any route that does not use the middleware.
       */
      stellarAddress?: string;
    }
  }
}

/**
 * Creates an Express middleware that authenticates requests via a SEP-10
 * signed challenge transaction.
 *
 * Expects an `Authorization: Bearer <base64-xdr>` header on every request,
 * where the value is a client-signed SEP-10 challenge XDR (as returned by
 * {@link generateChallenge} and signed by the client's Stellar wallet).
 *
 * On success the middleware sets `req.stellarAddress` to the verified G...
 * account ID and calls `next()`. On failure it short-circuits with a `401`
 * JSON response.
 *
 * **Reference pattern note:** this middleware re-verifies the raw challenge
 * transaction on every request. A production deployment would typically verify
 * once, then issue a short-lived session JWT so the full XDR is not sent
 * repeatedly — that session layer is intentionally out of scope for this
 * package.
 *
 * @param options - Server identity and domain values forwarded to
 *   {@link verifyChallenge}. See {@link VerifyChallengeOptions} for details.
 * @returns An Express {@link RequestHandler} that either populates
 *   `req.stellarAddress` and continues the chain, or responds with `401` and
 *   a JSON error body.
 */
export function createSep10Middleware(options: VerifyChallengeOptions): RequestHandler {
  return (req, res, next) => {
    const authHeader = req.header('Authorization') ?? '';
    const [scheme, token] = authHeader.split(' ');

    if (scheme !== 'Bearer' || !token) {
      res.status(401).json({ error: 'unauthorized', reason: 'missing bearer token' });
      return;
    }

    const result = verifyChallenge(token, options);

    if (!result.valid) {
      res.status(401).json({ error: 'unauthorized', reason: result.error });
      return;
    }

    req.stellarAddress = result.address;
    next();
  };
}
