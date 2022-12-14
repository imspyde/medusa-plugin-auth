"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildCallbackHandler = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
function buildCallbackHandler(domain, secret, expiresIn, successRedirect) {
    return (req, res) => {
        const tokenData = domain === 'admin' ? { userId: req.user.id } : { customer_id: req.user.id };
        const token = jsonwebtoken_1.default.sign(tokenData, secret, { expiresIn });
        const sessionKey = domain === 'admin' ? 'jwt' : 'jwt_store';
        req.session[sessionKey] = token;
        res.redirect(successRedirect);
    };
}
exports.buildCallbackHandler = buildCallbackHandler;
//# sourceMappingURL=build-callback-handler.js.map