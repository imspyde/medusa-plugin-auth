import { Router } from 'express';
import { ConfigModule, MedusaContainer } from '@medusajs/medusa/dist/types/global';
import { FacebookAuthOptions, Profile } from './types';
declare const FacebookStoreStrategy_base: new (...args: any[]) => any;
export declare class FacebookStoreStrategy extends FacebookStoreStrategy_base {
    protected readonly container: MedusaContainer;
    protected readonly configModule: ConfigModule;
    protected readonly strategyOptions: FacebookAuthOptions;
    constructor(container: MedusaContainer, configModule: ConfigModule, strategyOptions: FacebookAuthOptions);
    validate(req: Request, accessToken: string, refreshToken: string, profile: Profile): Promise<null | {
        id: string;
    }>;
    private defaultValidate;
}
/**
 * Return the router that hold the facebook store authentication routes
 * @param facebook
 * @param configModule
 */
export declare function getFacebookStoreAuthRouter(facebook: FacebookAuthOptions, configModule: ConfigModule): Router;
export {};
//# sourceMappingURL=store.d.ts.map