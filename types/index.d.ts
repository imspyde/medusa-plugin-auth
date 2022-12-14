import { GoogleAuthOptions } from '../auth-strategies/google';
import { FacebookAuthOptions } from '../auth-strategies/facebook';
import { LinkedinAuthOptions } from '../auth-strategies/linkedin';
import { ConfigModule, MedusaContainer } from '@medusajs/medusa/dist/types/global';
import { Router } from 'express';
import { Auth0Options } from '../auth-strategies/auth0';
export declare const CUSTOMER_METADATA_KEY = "useSocialAuth";
export declare const AUTH_PROVIDER_KEY = "authProvider";
export declare const TWENTY_FOUR_HOURS_IN_MS: number;
export declare type StrategyExport = {
    load: (container: MedusaContainer, configModule: ConfigModule, options?: unknown) => void;
    getRouter?: (configModule: ConfigModule, options: AuthOptions) => Router[];
};
export declare type AuthOptions = {
    google?: GoogleAuthOptions;
    facebook?: FacebookAuthOptions;
    linkedin?: LinkedinAuthOptions;
    auth0?: Auth0Options;
};
//# sourceMappingURL=index.d.ts.map