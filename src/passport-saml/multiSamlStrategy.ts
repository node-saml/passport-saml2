import * as saml from './saml';
import {CacheProvider as InMemoryCacheProvider} from './inmemory-cache-provider';
import SamlStrategy from './strategy';
import * as express from "express";
import { AuthenticateOptions, VerifyCallback, VerifyCallbackWithRequest } from './types';

interface MultiSamlOptions extends saml.SAMLOptions {
  passReqToCallback?: boolean;
  getSamlOptions(req: express.Request, cb: (err: Error | null, samlOptions?: Partial<saml.SAMLOptions>) => void): void;
}

class MultiSamlStrategy extends SamlStrategy {
  _options: MultiSamlOptions
  constructor(options: Partial<MultiSamlOptions>, verify: VerifyCallback | VerifyCallbackWithRequest) {
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

    super(options as saml.SAMLOptions, verify);
    this._options = options as MultiSamlOptions;
  }

  authenticate(req: express.Request, options: AuthenticateOptions) {
    this._options.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return this.error(err);
      }

      const _saml = new saml.SAML({...this._options, ...samlOptions});
      super.authenticate(req, {...options, _saml});
    });
  }

  logout(req: express.Request, callback: (err: Error | null) => null) {
    this._options.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return callback(err);
      }

      const _saml = new saml.SAML({...this._options, ...samlOptions});
      super.logout(req as saml.RequestWithUser, callback, {
        _saml 
      });
    });
  }

  generateServiceProviderMetadata(): string {
    throw new Error("Please use generateServiceProviderMetadataAsync instead");
  }

  generateServiceProviderMetadataAsync(req: express.Request, decryptionCert: string | null, signingCert: string, callback: (err: Error | null, metadata?: string) => void) {
    if (typeof callback !== 'function') {
      throw new Error("Metadata can't be provided synchronously for MultiSamlStrategy.");
    }

    return this._options.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return callback(err);
      }

      const _saml = new saml.SAML({...this._options, ...samlOptions});
      return callback(null, super.generateServiceProviderMetadata(decryptionCert, signingCert, { _saml }));
    });
  }
}

export = MultiSamlStrategy;
