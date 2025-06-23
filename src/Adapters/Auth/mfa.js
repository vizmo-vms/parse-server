/**
 * Parse Server authentication adapter for Multi-Factor Authentication (MFA).
 *
 * @class MFAAdapter
 * @param {Object} options - The adapter options.
 * @param {Array<String>} options.options - Supported MFA methods. Must include `"SMS"` or `"TOTP"`.
 * @param {Number} [options.digits=6] - The number of digits for the one-time password (OTP). Must be between 4 and 10.
 * @param {Number} [options.period=30] - The validity period of the OTP in seconds. Must be greater than 10.
 * @param {Object} [options.period={TOTP:30,SMS:30,EMAIL:150}] - The validity period of the OTP in seconds for different mfa factors. Must be greater than 30.
 * @param {String} [options.algorithm="SHA1"] - The algorithm used for TOTP generation. Defaults to `"SHA1"`.
 * @param {Function} [options.sendSMS] - A callback function for sending SMS OTPs. Required if `"SMS"` is included in `options`.
 *
 * @description
 * ## Parse Server Configuration
 * To configure Parse Server for MFA, use the following structure:
 * ```javascript
 * {
 *   auth: {
 *     mfa: {
 *       options: ["SMS", "TOTP"],
 *       digits: 6,
 *       period: 30,
 *       algorithm: "SHA1",
 *       sendSMS: (token, mobile) => {
 *         // Send the SMS using your preferred SMS provider.
 *         console.log(`Sending SMS to ${mobile} with token: ${token}`);
 *       }
 *     }
 *   }
 * }
 * ```
 *
 * ## MFA Methods
 * - **SMS**:
 *   - Requires a valid mobile number.
 *   - Sends a one-time password (OTP) via SMS for login or verification.
 *   - Uses the `sendSMS` callback for sending the OTP.
 *
 * - **TOTP**:
 *   - Requires a secret key for setup.
 *   - Validates the user's OTP against a time-based one-time password (TOTP) generated using the secret key.
 *   - Supports configurable digits, period, and algorithm for TOTP generation.
 *
 * ## MFA Payload
 * The adapter requires the following `authData` fields:
 * - **For SMS-based MFA**:
 *   - `mobile`: The user's mobile number (required for setup).
 *   - `token`: The OTP provided by the user for login or verification.
 * - **For TOTP-based MFA**:
 *   - `secret`: The TOTP secret key for the user (required for setup).
 *   - `token`: The OTP provided by the user for login or verification.
 *
 * ## Example Payloads
 * ### SMS Setup Payload
 * ```json
 * {
 *   "mobile": "+1234567890"
 * }
 * ```
 *
 * ### TOTP Setup Payload
 * ```json
 * {
 *   "secret": "BASE32ENCODEDSECRET",
 *   "token": "123456"
 * }
 * ```
 *
 * ### Login Payload
 * ```json
 * {
 *   "token": "123456"
 * }
 * ```
 *
 * @see {@link https://en.wikipedia.org/wiki/Time-based_One-Time_Password_algorithm Time-based One-Time Password Algorithm (TOTP)}
 * @see {@link https://tools.ietf.org/html/rfc6238 RFC 6238: TOTP: Time-Based One-Time Password Algorithm}
 */

import { TOTP, Secret } from 'otpauth';
import { randomString, sha256Hash } from '../../cryptoUtils';
import AuthAdapter from './AuthAdapter';
class MFAAdapter extends AuthAdapter {
  validateOptions(opts) {
    const validOptions = opts.options;
    if (!Array.isArray(validOptions)) {
      throw 'mfa.options must be an array';
    }
    this.sms = validOptions.includes('SMS');
    this.totp = validOptions.includes('TOTP');
    this.email = validOptions.includes('EMAIL');
    if (!this.sms && !this.totp && !this.email) {
      throw 'mfa.options must include SMS or TOTP or EMAIL';
    }
    const digits = opts.digits || 6;
    this.period = {};

    // Define default periods for each method
    const defaultPeriods = {
      SMS: 30, // 30 seconds for SMS
      EMAIL: 300, // 5 minutes for Email
      TOTP: 30, // 30 seconds for TOTP
    };

    if (typeof opts.period === 'number') {
      validOptions.forEach(method => {
        this.period[method] = opts.period;
      });
    } else if (opts.period && typeof opts.period === 'object') {
      Object.keys(opts.period).forEach(method => {
        if (opts.period.hasOwnProperty(method) && typeof opts.period[method] === 'number') {
          this.period[method] = opts.period[method] ?? defaultPeriods[method] ?? 30;
        }
      });
    } else {
      validOptions.forEach(method => {
        this.period[method] = defaultPeriods[method] ?? 30;
      });
    }
    if (typeof digits !== 'number') {
      throw 'mfa.digits must be a number';
    }
    if (digits < 4 || digits > 10) {
      throw 'mfa.digits must be between 4 and 10';
    }

    validOptions.forEach(method => {
      if (typeof this.period[method] !== 'number' || this.period[method] < 30) {
        throw `mfa.period.${method} must be a number greater than or equal to 30`;
      }
    });

    const sendSMS = opts.sendSMS;
    const sendEmail = opts.sendEmail;
    if (this.email && typeof sendEmail !== 'function') {
      throw 'mfa.sendEmail callback must be defined when using EMAIL OTPs';
    }
    if (this.sms && typeof sendSMS !== 'function') {
      throw 'mfa.sendSMS callback must be defined when using SMS OTPs';
    }
    this.smsCallback = sendSMS;
    this.emailCallback = sendEmail;
    this.digits = digits;
    this.algorithm = opts.algorithm || 'SHA1';
  }
  validateSetUp(mfaData) {
    if (mfaData.mobile && this.sms) {
      return this.setupMobileOTP(mfaData.mobile);
    }
    if (mfaData.email && this.email) {
      return this.setupEmailOTP(mfaData.email);
    }
    if (this.totp) {
      return this.setupTOTP(mfaData);
    }
    throw 'Invalid MFA data';
  }
  async validateLogin(loginData, _, req) {
    const saveResponse = {
      doNotSave: true,
    };
    const token = loginData.token;
    const auth = req.original.get('authData') || {};
    const { secret, recovery, mobile, email, token: saved, expiry } = auth.mfa || {};
    if (this.email && email) {
      if (token === 'request') {
        const { token: sendToken, expiry } = await this.sendEmail(email);
        auth.mfa = {
          token: sendToken,
          email: email,
          expiry: expiry,
        };
        // Use direct database access to avoid validation
        const query = new Parse.Query(Parse.User);
        const user = await query.get(req.object.id, { useMasterKey: true });
        user.set('authData', auth);

        // Skip validation and hooks
        await user.save(null, {
          useMasterKey: true,
          context: { skipValidation: true },
          validateSave: false,
        });

        throw new Parse.Error(209, 'Please enter the token');
      }
      if (!saved || token !== saved) {
        throw 'Invalid MFA token 1';
      }
      if (new Date() > expiry) {
        throw 'Invalid MFA token 2';
      }
      delete auth.mfa.token;
      delete auth.mfa.expiry;
      return {
        save: auth.mfa,
      };
    }
    if (this.sms && mobile) {
      if (token === 'request') {
        const { token: sendToken, expiry } = await this.sendSMS(mobile);
        auth.mfa.token = sendToken;
        auth.mfa.expiry = expiry;
        req.object.set('authData', auth);
        await req.object.save(null, { useMasterKey: true });
        throw 'Please enter the token';
      }
      if (!saved || token !== saved) {
        throw 'Invalid MFA token 1';
      }
      if (new Date() > expiry) {
        throw 'Invalid MFA token 2';
      }
      delete auth.mfa.token;
      delete auth.mfa.expiry;
      return {
        save: auth.mfa,
      };
    }
    if (this.totp) {
      if (typeof token !== 'string') {
        throw 'Invalid MFA token';
      }
      if (!secret) {
        return saveResponse;
      }
      if (recovery[0] === token || recovery[1] === token) {
        return saveResponse;
      }
      const totp = new TOTP({
        algorithm: this.algorithm,
        digits: this.digits,
        period: this.period['TOTP'],
        secret: Secret.fromBase32(secret),
      });
      const valid = totp.validate({
        token,
      });
      if (valid === null) {
        throw 'Invalid MFA token';
      }
    }
    return saveResponse;
  }
  async validateUpdate(authData, _, req) {
    if (req.master) {
      return;
    }
    if (authData.mobile && this.sms) {
      if (!authData.token) {
        throw 'Token required to confirm MFA changes.';
      }
      return this.confirmSMSOTP(authData, req.original.get('authData')?.mfa || {});
    }

    if (authData.email && this.email) {
      if (!authData.token) {
        throw 'Token required to confirm MFA changes.';
      }
      return this.confirmEmailOTP(authData, req.original.get('authData')?.mfa || {});
    }
    if (this.totp) {
      await this.validateLogin({ token: authData.old }, null, req);
      return this.validateSetUp(authData);
    }
    throw 'Invalid MFA data';
  }
  afterFind(authData, options, req) {
    if (req.master) {
      return;
    }

    let type;
    if (this.totp && authData.secret) {
      type = 'TOTP';
    } else if (this.sms && authData.mobile) {
      type = 'SMS';
    } else if (this.email && authData.email) {
      type = 'EMAIL';
    }

    if (type) {
      return {
        status: 'enabled',
        type,
      };
    }
    return {
      status: 'disabled',
    };
  }

  policy(req, auth) {
    if (this.sms && auth?.pending && Object.keys(auth).length === 1) {
      return 'default';
    }
    return 'additional';
  }

  async setupMobileOTP(mobile) {
    const { token, expiry } = await this.sendSMS(mobile);
    return {
      save: {
        pending: {
          [mobile]: {
            token,
            expiry,
          },
        },
      },
    };
  }

  async setupEmailOTP(email) {
    const { token, expiry } = await this.sendEmail(email);
    const emailHash = sha256Hash(email);
    return {
      save: {
        pending: {
          [emailHash]: {
            token,
            expiry,
          },
        },
      },
    };
  }

  async sendSMS(mobile) {
    if (!/^[+]*[(]{0,1}[0-9]{1,3}[)]{0,1}[-\s\./0-9]*$/g.test(mobile)) {
      throw 'Invalid mobile number.';
    }
    let token = '';
    while (token.length < this.digits) {
      token += randomString(10).replace(/\D/g, '');
    }
    token = token.substring(0, this.digits);
    await Promise.resolve(this.smsCallback(token, mobile));
    const expiry = new Date(new Date().getTime() + this.period['SMS'] * 1000);
    return { token, expiry };
  }

  async sendEmail(email) {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      throw 'Invalid email address.';
    }
    let token = '';
    while (token.length < this.digits) {
      token += randomString(10).replace(/\D/g, '');
    }
    token = token.substring(0, this.digits);
    await Promise.resolve(this.emailCallback(token, email));
    const expiry = new Date(new Date().getTime() + this.period['EMAIL'] * 1000);
    return { token, expiry };
  }
  async confirmSMSOTP(inputData, authData) {
    const { mobile, token } = inputData;
    if (!authData.pending?.[mobile]) {
      throw 'This number is not pending';
    }
    const pendingData = authData.pending[mobile];
    if (token !== pendingData.token) {
      throw 'Invalid MFA token';
    }
    if (new Date() > pendingData.expiry) {
      throw 'Invalid MFA token';
    }
    delete authData.pending[mobile];
    authData.mobile = mobile;
    return {
      save: authData,
    };
  }

  async confirmEmailOTP(inputData, authData) {
    const { email, token } = inputData;
    const emailHash = sha256Hash(email);
    if (!authData.pending?.[emailHash]) {
      throw 'This email is not pending';
    }
    const pendingData = authData.pending[emailHash];
    if (token !== pendingData.token) {
      throw 'Invalid MFA token';
    }
    if (new Date() > pendingData.expiry) {
      throw 'Invalid MFA token';
    }
    delete authData.pending[emailHash];
    authData.email = email;
    return {
      save: authData,
    };
  }

  setupTOTP(mfaData) {
    const { secret, token } = mfaData;
    if (!secret || !token || secret.length < 20) {
      throw 'Invalid MFA data';
    }
    const totp = new TOTP({
      algorithm: this.algorithm,
      digits: this.digits,
      period: this.period['TOTP'],
      secret: Secret.fromBase32(secret),
    });
    const valid = totp.validate({
      token,
    });
    if (valid === null) {
      throw 'Invalid MFA token';
    }
    const recovery = [randomString(30), randomString(30)];
    return {
      response: { recovery: recovery.join(', ') },
      save: { secret, recovery },
    };
  }
}
export default new MFAAdapter();
