import * as saml from "./saml";
export interface AuthenticateOptions {
    _saml: saml.SAML;
    additionalParams: any;
    samlFallback: 'login-request' | 'logout-request';
}

export type ValidateCallback = (err: Error | null, profile?: saml.Profile | null, loggedOut?: boolean) => void;
export type VerifyCallback = (profile?: saml.Profile | null, verified?: saml.VerifiedCallback) => void;
export type VerifyCallbackWithRequest = (req: saml.RequestWithUser, profile?: saml.Profile | null, info?: any) => void; 
