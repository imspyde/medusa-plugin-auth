"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __read = (this && this.__read) || function (o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var price_selection_strategy_1 = require("../interfaces/price-selection-strategy");
var tax_inclusive_pricing_1 = __importDefault(require("../loaders/feature-flags/tax-inclusive-pricing"));
var is_defined_1 = require("../utils/is-defined");
var PriceSelectionStrategy = /** @class */ (function (_super) {
    __extends(PriceSelectionStrategy, _super);
    function PriceSelectionStrategy(_a) {
        var manager = _a.manager, featureFlagRouter = _a.featureFlagRouter, moneyAmountRepository = _a.moneyAmountRepository;
        var _this = _super.call(this) || this;
        _this.manager_ = manager;
        _this.moneyAmountRepository_ = moneyAmountRepository;
        _this.featureFlagRouter_ = featureFlagRouter;
        return _this;
    }
    PriceSelectionStrategy.prototype.withTransaction = function (manager) {
        if (!manager) {
            return this;
        }
        return new PriceSelectionStrategy({
            manager: manager,
            moneyAmountRepository: this.moneyAmountRepository_,
            featureFlagRouter: this.featureFlagRouter_,
        });
    };
    PriceSelectionStrategy.prototype.calculateVariantPrice = function (variant_id, context) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                if (this.featureFlagRouter_.isFeatureEnabled(tax_inclusive_pricing_1.default.key)) {
                    return [2 /*return*/, this.calculateVariantPrice_new(variant_id, context)];
                }
                return [2 /*return*/, this.calculateVariantPrice_old(variant_id, context)];
            });
        });
    };
    PriceSelectionStrategy.prototype.calculateVariantPrice_new = function (variant_id, context) {
        var _a, _b, _c, _d, _e;
        return __awaiter(this, void 0, void 0, function () {
            var moneyRepo, _f, prices, count, result, taxRate, prices_1, prices_1_1, ma, isTaxInclusive;
            var e_1, _g;
            return __generator(this, function (_h) {
                switch (_h.label) {
                    case 0:
                        moneyRepo = this.manager_.getCustomRepository(this.moneyAmountRepository_);
                        return [4 /*yield*/, moneyRepo.findManyForVariantInRegion(variant_id, context.region_id, context.currency_code, context.customer_id, context.include_discount_prices, true)];
                    case 1:
                        _f = __read.apply(void 0, [_h.sent(), 2]), prices = _f[0], count = _f[1];
                        result = {
                            originalPrice: null,
                            calculatedPrice: null,
                            prices: prices,
                            originalPriceIncludesTax: null,
                            calculatedPriceIncludesTax: null,
                        };
                        if (!count || !context) {
                            return [2 /*return*/, result];
                        }
                        taxRate = (_a = context.tax_rates) === null || _a === void 0 ? void 0 : _a.reduce(function (accRate, nextTaxRate) {
                            return accRate + (nextTaxRate.rate || 0) / 100;
                        }, 0);
                        try {
                            for (prices_1 = __values(prices), prices_1_1 = prices_1.next(); !prices_1_1.done; prices_1_1 = prices_1.next()) {
                                ma = prices_1_1.value;
                                isTaxInclusive = ((_b = ma.currency) === null || _b === void 0 ? void 0 : _b.includes_tax) || false;
                                if ((_c = ma.price_list) === null || _c === void 0 ? void 0 : _c.includes_tax) {
                                    // PriceList specific price so use the PriceList tax setting
                                    isTaxInclusive = ma.price_list.includes_tax;
                                }
                                else if ((_d = ma.region) === null || _d === void 0 ? void 0 : _d.includes_tax) {
                                    // Region specific price so use the Region tax setting
                                    isTaxInclusive = ma.region.includes_tax;
                                }
                                delete ma.currency;
                                delete ma.region;
                                if (context.region_id &&
                                    ma.region_id === context.region_id &&
                                    ma.price_list_id === null &&
                                    ma.min_quantity === null &&
                                    ma.max_quantity === null) {
                                    result.originalPriceIncludesTax = isTaxInclusive;
                                    result.originalPrice = ma.amount;
                                }
                                if (context.currency_code &&
                                    ma.currency_code === context.currency_code &&
                                    ma.price_list_id === null &&
                                    ma.min_quantity === null &&
                                    ma.max_quantity === null &&
                                    result.originalPrice === null // region prices take precedence
                                ) {
                                    result.originalPriceIncludesTax = isTaxInclusive;
                                    result.originalPrice = ma.amount;
                                }
                                if (isValidQuantity(ma, context.quantity) &&
                                    isValidAmount(ma.amount, result, isTaxInclusive, taxRate) &&
                                    ((context.currency_code &&
                                        ma.currency_code === context.currency_code) ||
                                        (context.region_id && ma.region_id === context.region_id))) {
                                    result.calculatedPrice = ma.amount;
                                    result.calculatedPriceType = ((_e = ma.price_list) === null || _e === void 0 ? void 0 : _e.type) || price_selection_strategy_1.PriceType.DEFAULT;
                                    result.calculatedPriceIncludesTax = isTaxInclusive;
                                }
                            }
                        }
                        catch (e_1_1) { e_1 = { error: e_1_1 }; }
                        finally {
                            try {
                                if (prices_1_1 && !prices_1_1.done && (_g = prices_1.return)) _g.call(prices_1);
                            }
                            finally { if (e_1) throw e_1.error; }
                        }
                        return [2 /*return*/, result];
                }
            });
        });
    };
    PriceSelectionStrategy.prototype.calculateVariantPrice_old = function (variant_id, context) {
        var _a;
        return __awaiter(this, void 0, void 0, function () {
            var moneyRepo, _b, prices, count, result, prices_2, prices_2_1, ma;
            var e_2, _c;
            return __generator(this, function (_d) {
                switch (_d.label) {
                    case 0:
                        moneyRepo = this.manager_.getCustomRepository(this.moneyAmountRepository_);
                        return [4 /*yield*/, moneyRepo.findManyForVariantInRegion(variant_id, context.region_id, context.currency_code, context.customer_id, context.include_discount_prices)];
                    case 1:
                        _b = __read.apply(void 0, [_d.sent(), 2]), prices = _b[0], count = _b[1];
                        if (!count) {
                            return [2 /*return*/, {
                                    originalPrice: null,
                                    calculatedPrice: null,
                                    prices: [],
                                }];
                        }
                        result = {
                            originalPrice: null,
                            calculatedPrice: null,
                            prices: prices,
                        };
                        if (!context) {
                            return [2 /*return*/, result];
                        }
                        try {
                            for (prices_2 = __values(prices), prices_2_1 = prices_2.next(); !prices_2_1.done; prices_2_1 = prices_2.next()) {
                                ma = prices_2_1.value;
                                delete ma.currency;
                                delete ma.region;
                                if (context.region_id &&
                                    ma.region_id === context.region_id &&
                                    ma.price_list_id === null &&
                                    ma.min_quantity === null &&
                                    ma.max_quantity === null) {
                                    result.originalPrice = ma.amount;
                                }
                                if (context.currency_code &&
                                    ma.currency_code === context.currency_code &&
                                    ma.price_list_id === null &&
                                    ma.min_quantity === null &&
                                    ma.max_quantity === null &&
                                    result.originalPrice === null // region prices take precedence
                                ) {
                                    result.originalPrice = ma.amount;
                                }
                                if (isValidQuantity(ma, context.quantity) &&
                                    (result.calculatedPrice === null ||
                                        ma.amount < result.calculatedPrice) &&
                                    ((context.currency_code &&
                                        ma.currency_code === context.currency_code) ||
                                        (context.region_id && ma.region_id === context.region_id))) {
                                    result.calculatedPrice = ma.amount;
                                    result.calculatedPriceType = ((_a = ma.price_list) === null || _a === void 0 ? void 0 : _a.type) || price_selection_strategy_1.PriceType.DEFAULT;
                                }
                            }
                        }
                        catch (e_2_1) { e_2 = { error: e_2_1 }; }
                        finally {
                            try {
                                if (prices_2_1 && !prices_2_1.done && (_c = prices_2.return)) _c.call(prices_2);
                            }
                            finally { if (e_2) throw e_2.error; }
                        }
                        return [2 /*return*/, result];
                }
            });
        });
    };
    return PriceSelectionStrategy;
}(price_selection_strategy_1.AbstractPriceSelectionStrategy));
var isValidAmount = function (amount, result, isTaxInclusive, taxRate) {
    if (result.calculatedPrice === null) {
        return true;
    }
    if (isTaxInclusive === result.calculatedPriceIncludesTax) {
        // if both or neither are tax inclusive compare equally
        return amount < result.calculatedPrice;
    }
    if (typeof taxRate !== "undefined") {
        return isTaxInclusive
            ? amount < (1 + taxRate) * result.calculatedPrice
            : (1 + taxRate) * amount < result.calculatedPrice;
    }
    // if we dont have a taxrate we can't compare mixed prices
    return false;
};
var isValidQuantity = function (price, quantity) {
    return ((0, is_defined_1.isDefined)(quantity) && isValidPriceWithQuantity(price, quantity)) ||
        (typeof quantity === "undefined" && isValidPriceWithoutQuantity(price));
};
var isValidPriceWithoutQuantity = function (price) {
    return (!price.max_quantity && !price.min_quantity) ||
        ((!price.min_quantity || price.min_quantity === 0) && price.max_quantity);
};
var isValidPriceWithQuantity = function (price, quantity) {
    return (!price.min_quantity || price.min_quantity <= quantity) &&
        (!price.max_quantity || price.max_quantity >= quantity);
};
exports.default = PriceSelectionStrategy;
//# sourceMappingURL=price-selection.js.map