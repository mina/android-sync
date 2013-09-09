/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.gecko.background.fxa;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import org.json.simple.JSONObject;
import org.mozilla.gecko.sync.ExtendedJSONObject;
import org.mozilla.gecko.sync.Utils;
import org.mozilla.gecko.sync.net.SRPConstants;

public class FxAccount10AuthDelegate implements FxAccountClient.AuthDelegate {
  protected static final int HASH_LENGTH_BYTES = 16;
  protected static final int HASH_LENGTH_HEX = 2 * HASH_LENGTH_BYTES;

  // Fixed by protocol.
  protected final BigInteger N;
  protected final BigInteger g;
  protected final int byteLength;

  // Configured at construction time.
  protected final String email;
  protected final byte[] stretchedPWBytes;

  // All state is written by setParameters.
  protected String srpToken;
  protected String mainSalt;
  protected String srpSalt;

  protected BigInteger x;
  protected BigInteger A;
  protected byte[] Kbytes;
  protected byte[] Mbytes;

  public FxAccount10AuthDelegate(String email, byte[] stretchedPWBytes) {
    this.email = email;
    this.stretchedPWBytes = stretchedPWBytes;
    this.N = SRPConstants._2048.N;
    this.g = SRPConstants._2048.g;
    this.byteLength = SRPConstants._2048.byteLength;
  }

  protected BigInteger generateSecretValue() {
    return Utils.generateBigIntegerLessThan(N);
  }

  protected String hexModN(BigInteger value) {
    return FxAccountUtils.hexModN(value, N);
  }

  public static class FxAccountClientMalformedAuthException extends FxAccountClientException {
    private static final long serialVersionUID = 3585262174699395505L;

    public FxAccountClientMalformedAuthException(String detailMessage) {
      super(detailMessage);
    }
  }

  @SuppressWarnings("unchecked")
  @Override
  public JSONObject authStartBody() {
    final JSONObject body = new JSONObject();
    body.put("email", FxAccountUtils.bytes(email));
    return body;
  }

  @Override
  public void notifyAuthStartResponse(final ExtendedJSONObject body) throws FxAccountClientException {
    String srpToken = null;
    String srpSalt = null;
    String srpB = null;
    String mainSalt = null;

    try {
      srpToken = body.getString("srpToken");
      if (srpToken == null) {
        throw new FxAccountClientMalformedAuthException("srpToken must be a non-null object");
      }
      ExtendedJSONObject srp = body.getObject("srp");
      if (srp == null) {
        throw new FxAccountClientMalformedAuthException("srp must be a non-null object");
      }
      srpSalt = srp.getString("salt");
      if (srpSalt == null) {
        throw new FxAccountClientMalformedAuthException("srp.salt must not be null");
      }
      srpB = srp.getString("B");
      if (srpB == null) {
        throw new FxAccountClientMalformedAuthException("srp.B must not be null");
      }
      ExtendedJSONObject passwordStretching = body.getObject("passwordStretching");
      if (passwordStretching == null) {
        throw new FxAccountClientMalformedAuthException("passwordStretching must be a non-null object");
      }
      mainSalt = passwordStretching.getString("salt");
      if (mainSalt == null) {
        throw new FxAccountClientMalformedAuthException("srp.passwordStretching.salt must not be null");
      }
      throwIfParametersAreBad(passwordStretching);

      setParameters(srpToken, mainSalt, srpSalt, srpB, generateSecretValue());
    } catch (FxAccountClientException e) {
      throw e;
    } catch (Exception e) {
      throw new FxAccountClientException(e);
    }
  }

  /**
   * Expect object like:
   * "passwordStretching": {
   *   "type": "PBKDF2/scrypt/PBKDF2/v1",
   *   "PBKDF2_rounds_1": 20000,
   *   "scrypt_N": 65536,
   *   "scrypt_r": 8,
   *   "scrypt_p": 1,
   *   "PBKDF2_rounds_2": 20000,
   *   "salt": "996bc6b1aa63cd69856a2ec81cbf19d5c8a604713362df9ee15c2bf07128efab"
   * }
   * @param params to verify.
   * @throws FxAccountClientMalformedAuthException
   */
  protected void throwIfParametersAreBad(ExtendedJSONObject params) throws FxAccountClientMalformedAuthException {
    ExtendedJSONObject expected = new ExtendedJSONObject();
    expected.put("type", "PBKDF2/scrypt/PBKDF2/v1");
    expected.put("PBKDF2_rounds_1", 20000L);
    expected.put("scrypt_N", 65536L);
    expected.put("scrypt_r", 8L);
    expected.put("scrypt_p", 1L);
    expected.put("PBKDF2_rounds_2", 20000L);
    expected.put("salt", params.getString("salt"));
    if (!expected.equals(params)) {
      throw new FxAccountClientMalformedAuthException("malformed passwordStretching parameters: '" + params.toJSONString() + "'.");
    }
  }

  /**
   * All state is written in this method.
   */
  protected void setParameters(String srpToken, String mainSalt, String srpSalt, String srpB, BigInteger a) throws NoSuchAlgorithmException, UnsupportedEncodingException {
    this.srpToken = srpToken;
    this.mainSalt = mainSalt;
    this.srpSalt = srpSalt;

    this.x = FxAccountUtils.x(email.getBytes("UTF-8"), this.stretchedPWBytes, Utils.hex2Byte(srpSalt)); // XXX length?

    this.A = g.modPow(a, N);
    String srpA = hexModN(A);
    BigInteger B = new BigInteger(srpB, 16);

    byte[] srpABytes = Utils.hex2Byte(srpA);
    byte[] srpBBytes = Utils.hex2Byte(srpB);

    // u = H(pad(A) | pad(B))
    byte[] uBytes = Utils.sha256(Utils.concatAll(
        srpABytes,
        srpBBytes));
    BigInteger u = new BigInteger(Utils.byte2hex(uBytes, HASH_LENGTH_HEX), 16);

    // S = (B - k*g^x)^(a  u*x) % N
    // k = H(pad(N) | pad(g))
    int byteLength = (N.bitLength() + 7) / 8;
    byte[] kBytes = Utils.sha256(Utils.concatAll(
        Utils.hex2Byte(N.toString(16), byteLength),
        Utils.hex2Byte(g.toString(16), byteLength)));
    BigInteger k = new BigInteger(Utils.byte2hex(kBytes, HASH_LENGTH_HEX), 16);

    BigInteger base = B.subtract(k.multiply(g.modPow(x, N)).mod(N)).mod(N);
    BigInteger pow = a.add(u.multiply(x));
    BigInteger S = base.modPow(pow, N);
    String srpS = hexModN(S);

    byte[] sBytes = Utils.hex2Byte(srpS);

    // M = H(pad(A) | pad(B) | pad(S))
    this.Mbytes = Utils.sha256(Utils.concatAll(
        srpABytes,
        srpBBytes,
        sBytes));

    // K = H(pad(S))
    this.Kbytes = Utils.sha256(sBytes);
  }

  @SuppressWarnings("unchecked")
  @Override
  public JSONObject authFinishBody() throws FxAccountClientException {
    if (this.srpToken == null ||
        this.A == null ||
        this.Mbytes == null) {
      throw new FxAccountClientException("auth must be successfully notified before calling authFinishBody.");
    }
    JSONObject body = new JSONObject();
    body.put("srpToken", this.srpToken);
    body.put("A", hexModN(A));
    body.put("M", Utils.byte2hex(this.Mbytes, HASH_LENGTH_HEX));
    return body;
  }

  @Override
  public byte[] getSharedBytes() throws FxAccountClientException {
    if (this.Kbytes == null) {
      throw new FxAccountClientException("auth must be successfully finished before calling getSharedBytes.");
    }
    return this.Kbytes;
  }
}
