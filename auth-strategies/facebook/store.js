"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getFacebookStoreAuthRouter = exports.FacebookStoreStrategy = void 0;
const passport_1 = __importDefault(require("passport"));
const express_1 = require("express");
const cors_1 = __importDefault(require("cors"));
const passport_facebook_1 = require("passport-facebook");
const medusa_core_utils_1 = require("medusa-core-utils");
const types_1 = require("../../types");
const types_2 = require("./types");
const Strategy_1 = require("../../core/Strategy");
const build_callback_handler_1 = require("../../core/utils/build-callback-handler");
class FacebookStoreStrategy extends (0, Strategy_1.PassportStrategy)(passport_facebook_1.Strategy, types_2.FACEBOOK_STORE_STRATEGY_NAME) {
    constructor(container, configModule, strategyOptions) {
        super({
            clientID: strategyOptions.clientID,
            clientSecret: strategyOptions.clientSecret,
            callbackURL: strategyOptions.store.callbackUrl,
            passReqToCallback: true,
            profileFields: ['id', 'displayName', 'email', 'gender', 'name'],
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
                throw new medusa_core_utils_1.MedusaError(medusa_core_utils_1.MedusaError.Types.NOT_ALLOWED, `Your Facebook account does not contains any email and cannot be used`);
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
exports.FacebookStoreStrategy = FacebookStoreStrategy;
/**
 * Return the router that hold the facebook store authentication routes
 * @param facebook
 * @param configModule
 */
function getFacebookStoreAuthRouter(facebook, configModule) {
    var _a, _b, _c;
    const router = (0, express_1.Router)();
    const storeCorsOptions = {
        origin: configModule.projectConfig.store_cors.split(','),
        credentials: true,
    };
    const authPath = (_a = facebook.store.authPath) !== null && _a !== void 0 ? _a : '/store/auth/facebook';
    router.get(authPath, (0, cors_1.default)(storeCorsOptions));
    router.get(authPath, passport_1.default.authenticate(types_2.FACEBOOK_STORE_STRATEGY_NAME, {
        scope: ['email'],
        session: false,
    }));
    const expiresIn = (_b = facebook.store.expiresIn) !== null && _b !== void 0 ? _b : types_1.TWENTY_FOUR_HOURS_IN_MS;
    const callbackHandler = (0, build_callback_handler_1.buildCallbackHandler)('store', configModule.projectConfig.jwt_secret, expiresIn, facebook.store.successRedirect);
    const authPathCb = (_c = facebook.store.authCallbackPath) !== null && _c !== void 0 ? _c : '/store/auth/facebook/cb';
    router.get(authPathCb, (0, cors_1.default)(storeCorsOptions));
    router.get(authPathCb, (req, res, next) => {
        if (req.user) {
            return callbackHandler(req, res);
        }
        next();
    }, passport_1.default.authenticate(types_2.FACEBOOK_STORE_STRATEGY_NAME, {
        failureRedirect: facebook.store.failureRedirect,
        session: false,
    }), callbackHandler);
    return router;
}
exports.getFacebookStoreAuthRouter = getFacebookStoreAuthRouter;
//# sourceMappingURL=store.js.map