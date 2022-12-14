import { MedusaContainer } from '@medusajs/medusa/dist/types/global';
export declare const FACEBOOK_ADMIN_STRATEGY_NAME = "facebook.admin.medusa-auth-plugin";
export declare const FACEBOOK_STORE_STRATEGY_NAME = "facebook.store.medusa-auth-plugin";
export declare type Profile = {
    emails: {
        value: string;
    }[];
    name?: {
        givenName?: string;
        familyName?: string;
    };
};
export declare type FacebookAuthOptions = {
    clientID: string;
    clientSecret: string;
    admin?: {
        callbackUrl: string;
        successRedirect: string;
        failureRedirect: string;
        /**
         * Default /admin/auth/facebook
         */
        authPath?: string;
        /**
         * Default /admin/auth/facebook/cb
         */
        authCallbackPath?: string;
        /**
         * The default verify callback function will be used if this configuration is not specified
         */
        verifyCallback?: (container: MedusaContainer, req: Request, accessToken: string, refreshToken: string, profile: Profile) => Promise<null | {
            id: string;
        } | never>;
        expiresIn?: number;
    };
    store?: {
        callbackUrl: string;
        successRedirect: string;
        failureRedirect: string;
        /**
         * Default /store/auth/facebook
         */
        authPath?: string;
        /**
         * Default /store/auth/facebook/cb
         */
        authCallbackPath?: string;
        /**
         * The default verify callback function will be used if this configuration is not specified
         */
        verifyCallback?: (container: MedusaContainer, req: Request, accessToken: string, refreshToken: string, profile: Profile) => Promise<null | {
            id: string;
        } | never>;
        expiresIn?: number;
    };
};
//# sourceMappingURL=types.d.ts.map