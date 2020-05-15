import * as saml from './saml';
import {CacheProvider as InMemoryCacheProvider} from './inmemory-cache-provider';
import SamlStrategy from './strategy';
import * as express from "express";
import { AuthOptions, VerifyCallback } from './types';

interface MultiSamlOptions extends saml.SAMLOptions {
  getSamlOptions(req: express.Request, cb: (err: Error | null, samlOptions: saml.SAMLOptions) => void): void;
}

class MultiSamlStrategy extends SamlStrategy {
  _options: MultiSamlOptions
  constructor(options: MultiSamlOptions, verify: VerifyCallback) {
    if (!options || typeof options.getSamlOptions != 'function') {
      throw new Error('Please provide a getSamlOptions function');
    }

    if(!options.requestIdExpirationPeriodMs){
      options.requestIdExpirationPeriodMs = 28800000;  // 8 hours
    }

    if(!options.cacheProvider){
        options.cacheProvider = new InMemoryCacheProvider(
            {keyExpirationPeriodMs: options.requestIdExpirationPeriodMs });
    }

    super(options, verify);
    this._options = options;
  }

  authenticate(req: saml.RequestWithUser, options: AuthOptions) {
    this._options.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return this.error(err);
      }

      const _saml = new saml.SAML(Object.assign({}, this._options, samlOptions));
      super.authenticate(req, {...options, _saml});
    });
  }

  logout(req: saml.RequestWithUser, callback: (err: Error | null) => null) {
    this._options.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return callback(err);
      }

      const _saml = new saml.SAML(Object.assign({}, this._options, samlOptions));
      super.logout(req, callback, {
        _saml 
      });
    });
  }

  generateServiceProviderMetadata(): string {
    throw new Error("Please use generateServiceProviderMetadataAsync instead");
  }

  generateServiceProviderMetadataAsync(req: saml.RequestWithUser, decryptionCert: string, signingCert: string, callback: (err: Error | null, metadata?: string) => void) {
    if (typeof callback !== 'function') {
      throw new Error("Metadata can't be provided synchronously for MultiSamlStrategy.");
    }

    return this._options.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return callback(err);
      }

      const _saml = new saml.SAML(Object.assign({}, this._options, samlOptions));
      return callback(null, super.generateServiceProviderMetadata(decryptionCert, signingCert, { _saml }));
    });
  }
}

module.exports = MultiSamlStrategy;
