"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getAuth0AdminAuthRouter = exports.Auth0AdminStrategy = void 0;
const passport_1 = __importDefault(require("passport"));
const passport_auth0_1 = require("passport-auth0");
const types_1 = require("../../types");
const medusa_core_utils_1 = require("medusa-core-utils");
const express_1 = require("express");
const cors_1 = __importDefault(require("cors"));
const build_callback_handler_1 = require("../../core/utils/build-callback-handler");
const Strategy_1 = require("../../core/Strategy");
const types_2 = require("./types");
class Auth0AdminStrategy extends (0, Strategy_1.PassportStrategy)(passport_auth0_1.Strategy, types_2.AUTH0_ADMIN_STRATEGY_NAME) {
    constructor(container, configModule, strategyOptions) {
        super({
            domain: strategyOptions.auth0Domain,
            clientID: strategyOptions.clientID,
            clientSecret: strategyOptions.clientSecret,
            callbackURL: strategyOptions.admin.callbackUrl,
            passReqToCallback: true,
            state: true,
        });
        this.container = container;
        this.configModule = configModule;
        this.strategyOptions = strategyOptions;
    }
    async validate(req, accessToken, refreshToken, extraParams, profile) {
        if (this.strategyOptions.admin.verifyCallback) {
            return await this.strategyOptions.admin.verifyCallback(this.container, req, accessToken, refreshToken, extraParams, profile);
        }
        return await this.defaultValidate(profile);
    }
    async defaultValidate(profile) {
        var _a, _b;
        const userService = this.container.resolve('userService');
        const email = (_b = (_a = profile.emails) === null || _a === void 0 ? void 0 : _a[0]) === null || _b === void 0 ? void 0 : _b.value;
        if (!email) {
            throw new medusa_core_utils_1.MedusaError(medusa_core_utils_1.MedusaError.Types.NOT_ALLOWED, `Your Auth0 account does not contain a valid email and cannot be used`);
        }
        const user = await userService.retrieveByEmail(email).catch(() => void 0);
        if (user) {
            if (!user.metadata || user.metadata[types_1.AUTH_PROVIDER_KEY] !== types_2.AUTH0_ADMIN_STRATEGY_NAME) {
                throw new medusa_core_utils_1.MedusaError(medusa_core_utils_1.MedusaError.Types.INVALID_DATA, `Admin with email ${email} already exists`);
            }
        }
        else {
            throw new medusa_core_utils_1.MedusaError(medusa_core_utils_1.MedusaError.Types.NOT_ALLOWED, `Unable to authenticate the user with the email ${email}`);
        }
        return { id: user.id };
    }
}
exports.Auth0AdminStrategy = Auth0AdminStrategy;
/**
 * Return the router that holds the auth0 admin authentication routes
 * @param auth0
 * @param configModule
 */
function getAuth0AdminAuthRouter(auth0, configModule) {
    var _a, _b, _c;
    const router = (0, express_1.Router)();
    const adminCorsOptions = {
        origin: configModule.projectConfig.admin_cors.split(','),
        credentials: true,
    };
    const authPath = (_a = auth0.admin.authPath) !== null && _a !== void 0 ? _a : '/admin/auth/auth0';
    router.get(authPath, (0, cors_1.default)(adminCorsOptions));
    router.get(authPath, passport_1.default.authenticate(types_2.AUTH0_ADMIN_STRATEGY_NAME, {
        scope: 'openid email profile',
        session: false,
    }));
    const expiresIn = (_b = auth0.admin.expiresIn) !== null && _b !== void 0 ? _b : types_1.TWENTY_FOUR_HOURS_IN_MS;
    const callbackHandler = (0, build_callback_handler_1.buildCallbackHandler)('admin', configModule.projectConfig.jwt_secret, expiresIn, auth0.admin.successRedirect);
    const authPathCb = (_c = auth0.admin.authCallbackPath) !== null && _c !== void 0 ? _c : '/admin/auth/auth0/cb';
    router.get(authPathCb, (0, cors_1.default)(adminCorsOptions));
    router.get(authPathCb, (req, res, next) => {
        if (req.user) {
            callbackHandler(req, res);
        }
        next();
    }, passport_1.default.authenticate(types_2.AUTH0_ADMIN_STRATEGY_NAME, {
        failureRedirect: auth0.admin.failureRedirect,
        session: false,
    }), callbackHandler);
    return router;
}
exports.getAuth0AdminAuthRouter = getAuth0AdminAuthRouter;
//# sourceMappingURL=admin.js.map