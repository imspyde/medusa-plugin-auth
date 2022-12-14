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
Object.defineProperty(exports, "__esModule", { value: true });
exports.isSearchService = exports.AbstractSearchService = void 0;
var transaction_base_service_1 = require("./transaction-base-service");
var medusa_interfaces_1 = require("medusa-interfaces");
var AbstractSearchService = /** @class */ (function (_super) {
    __extends(AbstractSearchService, _super);
    function AbstractSearchService(container, options) {
        var _this = _super.call(this, container, options) || this;
        _this.options_ = options;
        return _this;
    }
    Object.defineProperty(AbstractSearchService.prototype, "options", {
        get: function () {
            return this.options_;
        },
        enumerable: false,
        configurable: true
    });
    return AbstractSearchService;
}(transaction_base_service_1.TransactionBaseService));
exports.AbstractSearchService = AbstractSearchService;
function isSearchService(obj) {
    return obj instanceof AbstractSearchService || obj instanceof medusa_interfaces_1.SearchService;
}
exports.isSearchService = isSearchService;
//# sourceMappingURL=search-service.js.map