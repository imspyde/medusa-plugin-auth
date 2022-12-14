"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getGoogleAdminAuthRouter = exports.GoogleAdminStrategy = void 0;
const passport_1 = __importDefault(require("passport"));
const passport_google_oauth2_1 = require("passport-google-oauth2");
const types_1 = require("../../types");
const medusa_core_utils_1 = require("medusa-core-utils");
const express_1 = require("express");
const cors_1 = __importDefault(require("cors"));
const types_2 = require("./types");
const Strategy_1 = require("../../core/Strategy");
const build_callback_handler_1 = require("../../core/utils/build-callback-handler");
class GoogleAdminStrategy extends (0, Strategy_1.PassportStrategy)(passport_google_oauth2_1.Strategy, types_2.GOOGLE_ADMIN_STRATEGY_NAME) {
    constructor(container, configModule, strategyOptions) {
        super({
            clientID: strategyOptions.clientID,
            clientSecret: strategyOptions.clientSecret,
            callbackURL: strategyOptions.admin.callbackUrl,
            passReqToCallback: true,
        });
        this.container = container;
        this.configModule = configModule;
        this.strategyOptions = strategyOptions;
    }
    async validate(req, accessToken, refreshToken, profile) {
        if (this.strategyOptions.admin.verifyCallback) {
            return await this.strategyOptions.admin.verifyCallback(this.container, req, accessToken, refreshToken, profile);
        }
        return await this.defaultValidate(profile);
    }
    async defaultValidate(profile) {
        var _a, _b;
        const userService = this.container.resolve('userService');
        const email = (_b = (_a = profile.emails) === null || _a === void 0 ? void 0 : _a[0]) === null || _b === void 0 ? void 0 : _b.value;
        if (!email) {
            throw new medusa_core_utils_1.MedusaError(medusa_core_utils_1.MedusaError.Types.NOT_ALLOWED, `Your Google account does not contains any email and cannot be used`);
        }
        const user = await userService.retrieveByEmail(email).catch(() => void 0);
        if (!user) {
            throw new medusa_core_utils_1.MedusaError(medusa_core_utils_1.MedusaError.Types.NOT_ALLOWED, `Unable to authenticate the user with the email ${email}`);
        }
        return { id: user.id };
    }
}
exports.GoogleAdminStrategy = GoogleAdminStrategy;
/**
 * Return the router that hold the google admin authentication routes
 * @param google
 * @param configModule
 */
function getGoogleAdminAuthRouter(google, configModule) {
    var _a, _b, _c;
    const router = (0, express_1.Router)();
    const adminCorsOptions = {
        origin: configModule.projectConfig.admin_cors.split(','),
        credentials: true,
    };
    const authPath = (_a = google.admin.authPath) !== null && _a !== void 0 ? _a : '/admin/auth/google';
    router.get(authPath, (0, cors_1.default)(adminCorsOptions));
    router.get(authPath, passport_1.default.authenticate(types_2.GOOGLE_ADMIN_STRATEGY_NAME, {
        scope: [
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
        ],
        session: false,
    }));
    const expiresIn = (_b = google.admin.expiresIn) !== null && _b !== void 0 ? _b : types_1.TWENTY_FOUR_HOURS_IN_MS;
    const callbackHandler = (0, build_callback_handler_1.buildCallbackHandler)('admin', configModule.projectConfig.jwt_secret, expiresIn, google.admin.successRedirect);
    const authPathCb = (_c = google.admin.authCallbackPath) !== null && _c !== void 0 ? _c : '/admin/auth/google/cb';
    router.get(authPathCb, (0, cors_1.default)(adminCorsOptions));
    router.get(authPathCb, (req, res, next) => {
        if (req.user) {
            return callbackHandler(req, res);
        }
        next();
    }, passport_1.default.authenticate(types_2.GOOGLE_ADMIN_STRATEGY_NAME, {
        failureRedirect: google.admin.failureRedirect,
        session: false,
    }), callbackHandler);
    return router;
}
exports.getGoogleAdminAuthRouter = getGoogleAdminAuthRouter;
//# sourceMappingURL=admin.js.map