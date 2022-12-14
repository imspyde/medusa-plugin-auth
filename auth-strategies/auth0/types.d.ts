import { MedusaContainer } from '@medusajs/medusa/dist/types/global';
export declare const AUTH0_ADMIN_STRATEGY_NAME = "auth0.admin.medusa-auth-plugin";
export declare const AUTH0_STORE_STRATEGY_NAME = "auth0.store.medusa-auth-plugin";
export declare type Profile = {
    emails: {
        value: string;
    }[];
    name?: {
        givenName?: string;
        familyName?: string;
    };
};
export declare type ExtraParams = {
    audience?: string | undefined;
    connection?: string | undefined;
    prompt?: string | undefined;
};
export declare type Auth0Options = {
    clientID: string;
    clientSecret: string;
    auth0Domain: string;
    admin?: {
        callbackUrl: string;
        successRedirect: string;
        failureRedirect: string;
        /**
         * Default /admin/auth/auth0
         */
        authPath?: string;
        /**
         * Default /admin/auth/auth0/cb
         */
        authCallbackPath?: string;
        /**
         * The default verify callback function will be used if this configuration is not specified
         */
        verifyCallback?: (container: MedusaContainer, req: Request, accessToken: string, refreshToken: string, extraParams: ExtraParams, profile: Profile) => Promise<null | {
            id: string;
        } | never>;
        expiresIn?: number;
    };
    store?: {
        callbackUrl: string;
        successRedirect: string;
        failureRedirect: string;
        /**
         * Default /store/auth/auth0
         */
        authPath?: string;
        /**
         * Default /store/auth/auth0/cb
         */
        authCallbackPath?: string;
        /**
         * The default verify callback function will be used if this configuration is not specified
         */
        verifyCallback?: (container: MedusaContainer, req: Request, accessToken: string, refreshToken: string, extraParams: ExtraParams, profile: Profile) => Promise<null | {
            id: string;
        } | never>;
        expiresIn?: number;
    };
};
//# sourceMappingURL=types.d.ts.map