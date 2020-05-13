const passport = require('passport-strategy');
const util = require('util');
const saml = require('./saml');
const url = require('url');

function Strategy (options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }

  if (!verify) {
    throw new Error('SAML authentication strategy requires a verify function');
  }

  // Customizing the name can be useful to support multiple SAML configurations at the same time.
  // Unlike other options, this one gets deleted instead of passed along.
  if  (options.name) {
    this.name  = options.name;
  }
  else {
    this.name = 'saml';
  }

  passport.Strategy.call(this);

  this._verify = verify;
  this._saml = new saml.SAML(options);
  this._passReqToCallback = !!options.passReqToCallback;
  this._authnRequestBinding = options.authnRequestBinding || 'HTTP-Redirect';
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function (req, options) {
  const self = this;
  const saml = options._saml || this._saml;
  options.samlFallback = options.samlFallback || 'login-request';

  function validateCallback(err, profile, loggedOut) {
      if (err) {
        return self.error(err);
      }

      if (loggedOut) {
        req.logout();
        if (profile) {
          req.samlLogoutRequest = profile;
          return self._saml.getLogoutResponseUrl(req, options, redirectIfSuccess);
        }
        return self.pass();
      }

      const verified = function (err, user, info) {
        if (err) {
          return self.error(err);
        }

        if (!user) {
          return self.fail(info);
        }

        self.success(user, info);
      };

      if (self._passReqToCallback) {
        self._verify(req, profile, verified);
      } else {
        self._verify(profile, verified);
      }
  }

  function redirectIfSuccess(err, url) {
    if (err) {
      self.error(err);
    } else {
      self.redirect(url);
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
      'login-request': function() {
        if (self._authnRequestBinding === 'HTTP-POST') {
          saml.getAuthorizeForm(req, function(err, data) {
            if (err) {
              self.error(err);
            } else {
              const res = req.res;
              res.send(data);
            }
          });
        } else { // Defaults to HTTP-Redirect
          saml.getAuthorizeUrl(req, options, redirectIfSuccess);
        }
      }.bind(self),
      'logout-request': function() {
          saml.getLogoutUrl(req, options, redirectIfSuccess);
      }.bind(self)
    }[options.samlFallback];

    if (typeof requestHandler !== 'function') {
      return self.fail();
    }

    requestHandler();
  }
};

Strategy.prototype.logout = function(req, callback, options) {
  const saml = options && options._saml ? options._saml : this._saml;
  saml.getLogoutUrl(req, {}, callback);
};

Strategy.prototype.generateServiceProviderMetadata = function( decryptionCert, signingCert, options) {
  const saml = options && options._saml ? options._saml : this._saml;
  return saml.generateServiceProviderMetadata( decryptionCert, signingCert );
};

module.exports = Strategy;
