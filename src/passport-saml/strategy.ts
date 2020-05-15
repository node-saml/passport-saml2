import passport from 'passport-strategy';
import * as saml from './saml';
import url from 'url';
import { AuthOptions, VerifyCallback } from './types';

type VerifyCallbackWithRequest = (req: saml.RequestWithUser, profile?: saml.Profile | null, info?: any) => void; 

class Strategy extends passport.Strategy {
  _saml: saml.SAML;
  _verify: VerifyCallback | VerifyCallbackWithRequest;
  name: string;
  fail!: (info?: any) => void;
  redirect!: (url: string) => void;
  pass!: () => void;
  _passReqToCallback: boolean;
  error!: (err: Error) => void;
  success!: (user: saml.Profile, info: any) => void;
  _authnRequestBinding: string;

  constructor(options: saml.SAMLOptions, verify: VerifyCallback) {
    if (typeof options == 'function') {
      verify = options;
      options = {} as saml.SAMLOptions;
    }

    if (!verify) {
      throw new Error('SAML authentication strategy requires a verify function');
    }

    super();
    // Customizing the name can be useful to support multiple SAML configurations at the same time.
    // Unlike other options, this one gets deleted instead of passed along.
    if (options.name) {
      this.name = options.name;
    }
    else {
      this.name = 'saml';
    }

    this._verify = verify;
    this._saml = new saml.SAML(options);
    this._passReqToCallback = !!options.passReqToCallback;
    this._authnRequestBinding = options.authnRequestBinding || 'HTTP-Redirect';
  }

  logout(req: saml.RequestWithUser, callback: (err: Error | null) => null, options: {_saml: saml.SAML}) {
    const saml = options && options._saml ? options._saml : this._saml;
    saml.getLogoutUrl(req, {}, callback);
  }

  generateServiceProviderMetadata(decryptionCert: string, signingCert: string, options: {_saml: saml.SAML}) {
    const saml = options && options._saml ? options._saml : this._saml;
    return saml.generateServiceProviderMetadata(decryptionCert, signingCert);
  }

  authenticate(req: saml.RequestWithUser, options: AuthOptions) {
    const saml = options._saml || this._saml;
    options.samlFallback = options.samlFallback || 'login-request';

    const redirectIfSuccess = (err: Error | null, url?: string) => {
      if (err) {
        this.error(err);
      } else {
        this.redirect(url!);
      }
    }

    const validateCallback = (err: Error | null, profile?: saml.Profile | null, loggedOut?: boolean): void => {
  
      if (err) {
        return this.error(err);
      }

      if (loggedOut) {
        req.logout();
        if (profile) {
          req.samlLogoutRequest = profile;
          return this._saml.getLogoutResponseUrl(req, options, redirectIfSuccess);
        }
        return this.pass();
      }

      const verified = (err: Error | null, user?: saml.Profile | null, info?: any) => {
        if (err) {
          return this.error(err);
        }

        if (!user) {
          return this.fail(info);
        }

        this.success(user, info);
      };

      if (this._passReqToCallback) {
        (this._verify as VerifyCallbackWithRequest)(req, profile, verified);
      } else {
        (this._verify as VerifyCallback)(profile, verified);
      }
    }

    if (req.query && (req.query.SAMLResponse || req.query.SAMLRequest)) {
      const originalQuery = url.parse(req.url).query;
      saml.validateRedirect(req.query, originalQuery, validateCallback);
    } else if (req.body && req.body.SAMLResponse) {
      saml.validatePostResponse(req.body, validateCallback);
    } else if (req.body && req.body.SAMLRequest) {
      saml.validatePostRequest(req.body, validateCallback);
    } else {
      const requestHandler = {
        'login-request': (): void => {
          if (this._authnRequestBinding === 'HTTP-POST') {
            saml.getAuthorizeForm(req, (err, data) => {
              if (err) {
                this.error(err);
              } else {
                const res = req.res!;
                res.send(data);
              }
            });
          } else { // Defaults to HTTP-Redirect
            saml.getAuthorizeUrl(req, options, redirectIfSuccess);
          }
        },
        'logout-request': () => {
          saml.getLogoutUrl(req, options, redirectIfSuccess);
        }
      }[options.samlFallback];

      if (typeof requestHandler !== 'function') {
        return this.fail();
      }

      requestHandler();
    }
  }
}


export = Strategy;
