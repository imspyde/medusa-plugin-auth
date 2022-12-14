"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getLinkedinStoreAuthRouter = exports.LinkedinStoreStrategy = void 0;
const passport_1 = __importDefault(require("passport"));
const express_1 = require("express");
const cors_1 = __importDefault(require("cors"));
const passport_linkedin_oauth2_1 = require("passport-linkedin-oauth2");
const medusa_core_utils_1 = require("medusa-core-utils");
const types_1 = require("../../types");
const Strategy_1 = require("../../core/Strategy");
const types_2 = require("./types");
const build_callback_handler_1 = require("../../core/utils/build-callback-handler");
class LinkedinStoreStrategy extends (0, Strategy_1.PassportStrategy)(passport_linkedin_oauth2_1.Strategy, types_2.LINKEDIN_STORE_STRATEGY_NAME) {
    constructor(container, configModule, strategyOptions) {
        super({
            clientID: strategyOptions.clientID,
            clientSecret: strategyOptions.clientSecret,
            callbackURL: strategyOptions.store.callbackUrl,
            passReqToCallback: true,
            scope: ['r_emailaddress'],
            state: true,
        });
        this.container = container;
        this.configModule = configModule;
        this.strategyOptions = strategyOptions;
    }
    async validate(req, accessToken, refreshToken, profile) {
        if (this.strategyOptions.store.verifyCallback) {
            return await this.strategyOptions.store.verifyCallback(this.container, req, accessToken, refreshToken, profile);
        }
        return await this.defaultValidate(profile);
    }
    async defaultValidate(profile) {
        const manager = this.container.resolve('manager');
        const customerService = this.container.resolve('customerService');
        return await manager.transaction(async (transactionManager) => {
            var _a, _b, _c, _d;
            const email = (_b = (_a = profile.emails) === null || _a === void 0 ? void 0 : _a[0]) === null || _b === void 0 ? void 0 : _b.value;
            if (!email) {
                throw new medusa_core_utils_1.MedusaError(medusa_core_utils_1.MedusaError.Types.NOT_ALLOWED, `Your Linkedin account does not contains any email and cannot be used`);
            }
            const customer = await customerService
                .withTransaction(transactionManager)
                .retrieveByEmail(email)
                .catch(() => void 0);
            if (customer) {
                if (!customer.metadata || !customer.metadata[types_1.CUSTOMER_METADATA_KEY]) {
                    throw new medusa_core_utils_1.MedusaError(medusa_core_utils_1.MedusaError.Types.INVALID_DATA, `Customer with email ${email} already exists`);
                }
                else {
                    return { id: customer.id };
                }
            }
            return await customerService
                .withTransaction(transactionManager)
                .create({
                email,
                metadata: {
                    [types_1.CUSTOMER_METADATA_KEY]: true,
                },
                first_name: (_c = profile === null || profile === void 0 ? void 0 : profile.name.givenName) !== null && _c !== void 0 ? _c : '',
                last_name: (_d = profile === null || profile === void 0 ? void 0 : profile.name.familyName) !== null && _d !== void 0 ? _d : '',
            })
                .then((customer) => {
                return { id: customer.id };
            });
        });
    }
}
exports.LinkedinStoreStrategy = LinkedinStoreStrategy;
/**
 * Return the router that hold the linkedin store authentication routes
 * @param linkedin
 * @param configModule
 */
function getLinkedinStoreAuthRouter(linkedin, configModule) {
    var _a, _b, _c;
    const router = (0, express_1.Router)();
    const storeCorsOptions = {
        origin: configModule.projectConfig.store_cors.split(','),
        credentials: true,
    };
    const authPath = (_a = linkedin.store.authPath) !== null && _a !== void 0 ? _a : '/store/auth/linkedin';
    router.get(authPath, (0, cors_1.default)(storeCorsOptions));
    router.get(authPath, passport_1.default.authenticate(types_2.LINKEDIN_STORE_STRATEGY_NAME, {
        scope: [
            'https://www.linkedinapis.com/auth/userinfo.email',
            'https://www.linkedinapis.com/auth/userinfo.profile',
        ],
        session: false,
    }));
    const expiresIn = (_b = linkedin.store.expiresIn) !== null && _b !== void 0 ? _b : types_1.TWENTY_FOUR_HOURS_IN_MS;
    const callbackHandler = (0, build_callback_handler_1.buildCallbackHandler)('store', configModule.projectConfig.jwt_secret, expiresIn, linkedin.store.successRedirect);
    const authPathCb = (_c = linkedin.store.authCallbackPath) !== null && _c !== void 0 ? _c : '/store/auth/linkedin/cb';
    router.get(authPathCb, (0, cors_1.default)(storeCorsOptions));
    router.get(authPathCb, (req, res, next) => {
        if (req.user) {
            callbackHandler(req, res);
        }
        next();
    }, passport_1.default.authenticate(types_2.LINKEDIN_STORE_STRATEGY_NAME, {
        failureRedirect: linkedin.store.failureRedirect,
        session: false,
    }), callbackHandler);
    return router;
}
exports.getLinkedinStoreAuthRouter = getLinkedinStoreAuthRouter;
//# sourceMappingURL=store.js.map