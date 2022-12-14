"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
var __values = (this && this.__values) || function(o) {
    var s = typeof Symbol === "function" && Symbol.iterator, m = s && o[s], i = 0;
    if (m) return m.call(o);
    if (o && typeof o.length === "number") return {
        next: function () {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
    throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.defaultStoreCartRelations = exports.defaultStoreCartFields = void 0;
var express_1 = require("express");
require("reflect-metadata");
var common_1 = require("../../../../types/common");
var middlewares_1 = __importStar(require("../../../middlewares"));
var update_cart_1 = require("./update-cart");
var create_cart_1 = require("./create-cart");
var route = (0, express_1.Router)();
exports.default = (function (app, container) {
    var e_1, _a;
    var middlewareService = container.resolve("middlewareService");
    var featureFlagRouter = container.resolve("featureFlagRouter");
    app.use("/carts", route);
    if (featureFlagRouter.isFeatureEnabled("sales_channels")) {
        exports.defaultStoreCartRelations.push("sales_channel");
    }
    // Inject plugin routes
    var routers = middlewareService.getRouters("store/carts");
    try {
        for (var routers_1 = __values(routers), routers_1_1 = routers_1.next(); !routers_1_1.done; routers_1_1 = routers_1.next()) {
            var router = routers_1_1.value;
            route.use("/", router);
        }
    }
    catch (e_1_1) { e_1 = { error: e_1_1 }; }
    finally {
        try {
            if (routers_1_1 && !routers_1_1.done && (_a = routers_1.return)) _a.call(routers_1);
        }
        finally { if (e_1) throw e_1.error; }
    }
    route.get("/:id", (0, middlewares_1.transformQuery)(common_1.FindParams, {
        defaultRelations: exports.defaultStoreCartRelations,
        defaultFields: exports.defaultStoreCartFields,
        isList: false,
    }), middlewares_1.default.wrap(require("./get-cart").default));
    route.post("/", middlewareService.usePreCartCreation(), (0, middlewares_1.transformBody)(create_cart_1.StorePostCartReq), middlewares_1.default.wrap(require("./create-cart").default));
    route.post("/:id", (0, middlewares_1.transformBody)(update_cart_1.StorePostCartsCartReq), middlewares_1.default.wrap(require("./update-cart").default));
    route.post("/:id/complete", middlewares_1.default.wrap(require("./complete-cart").default));
    // DEPRECATION
    route.post("/:id/complete-cart", middlewares_1.default.wrap(require("./complete-cart").default));
    // Line items
    route.post("/:id/line-items", middlewares_1.default.wrap(require("./create-line-item").default));
    route.post("/:id/line-items/:line_id", middlewares_1.default.wrap(require("./update-line-item").default));
    route.delete("/:id/line-items/:line_id", middlewares_1.default.wrap(require("./delete-line-item").default));
    route.delete("/:id/discounts/:code", middlewares_1.default.wrap(require("./delete-discount").default));
    // Payment sessions
    route.post("/:id/payment-sessions", middlewares_1.default.wrap(require("./create-payment-sessions").default));
    route.post("/:id/payment-sessions/:provider_id", middlewares_1.default.wrap(require("./update-payment-session").default));
    route.delete("/:id/payment-sessions/:provider_id", middlewares_1.default.wrap(require("./delete-payment-session").default));
    route.post("/:id/payment-sessions/:provider_id/refresh", middlewares_1.default.wrap(require("./refresh-payment-session").default));
    route.post("/:id/payment-session", middlewares_1.default.wrap(require("./set-payment-session").default));
    // Shipping Options
    route.post("/:id/shipping-methods", middlewares_1.default.wrap(require("./add-shipping-method").default));
    // Taxes
    route.post("/:id/taxes", middlewares_1.default.wrap(require("./calculate-taxes").default));
    return app;
});
exports.defaultStoreCartFields = [];
exports.defaultStoreCartRelations = [
    "gift_cards",
    "region",
    "items",
    "items.adjustments",
    "payment",
    "shipping_address",
    "billing_address",
    "region.countries",
    "region.payment_providers",
    "shipping_methods",
    "payment_sessions",
    "shipping_methods.shipping_option",
    "discounts",
    "discounts.rule",
];
__exportStar(require("./add-shipping-method"), exports);
__exportStar(require("./create-cart"), exports);
__exportStar(require("./create-line-item"), exports);
__exportStar(require("./create-payment-sessions"), exports);
__exportStar(require("./set-payment-session"), exports);
__exportStar(require("./update-cart"), exports);
__exportStar(require("./update-line-item"), exports);
__exportStar(require("./update-payment-session"), exports);
//# sourceMappingURL=index.js.map