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
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.extendedFindParamsMixin = exports.FindPaginationParams = exports.FindParams = exports.AddressCreatePayload = exports.AddressPayload = exports.NumericalComparisonOperator = exports.StringComparisonOperator = exports.DateComparisonOperator = exports.EmptyQueryParams = void 0;
var class_transformer_1 = require("class-transformer");
var class_validator_1 = require("class-validator");
require("reflect-metadata");
var date_transform_1 = require("../utils/validators/date-transform");
var EmptyQueryParams = /** @class */ (function () {
    function EmptyQueryParams() {
    }
    return EmptyQueryParams;
}());
exports.EmptyQueryParams = EmptyQueryParams;
var DateComparisonOperator = /** @class */ (function () {
    function DateComparisonOperator() {
    }
    __decorate([
        (0, class_validator_1.IsOptional)(),
        (0, class_validator_1.IsDate)(),
        (0, class_transformer_1.Transform)(date_transform_1.transformDate),
        __metadata("design:type", Date)
    ], DateComparisonOperator.prototype, "lt", void 0);
    __decorate([
        (0, class_validator_1.IsOptional)(),
        (0, class_validator_1.IsDate)(),
        (0, class_transformer_1.Transform)(date_transform_1.transformDate),
        __metadata("design:type", Date)
    ], DateComparisonOperator.prototype, "gt", void 0);
    __decorate([
        (0, class_validator_1.IsOptional)(),
        (0, class_validator_1.IsDate)(),
        (0, class_transformer_1.Transform)(date_transform_1.transformDate),
        __metadata("design:type", Date)
    ], DateComparisonOperator.prototype, "gte", void 0);
    __decorate([
        (0, class_validator_1.IsOptional)(),
        (0, class_validator_1.IsDate)(),
        (0, class_transformer_1.Transform)(date_transform_1.transformDate),
        __metadata("design:type", Date)
    ], DateComparisonOperator.prototype, "lte", void 0);
    return DateComparisonOperator;
}());
exports.DateComparisonOperator = DateComparisonOperator;
var StringComparisonOperator = /** @class */ (function () {
    function StringComparisonOperator() {
    }
    __decorate([
        (0, class_validator_1.IsString)(),
        (0, class_validator_1.IsOptional)(),
        __metadata("design:type", String)
    ], StringComparisonOperator.prototype, "lt", void 0);
    __decorate([
        (0, class_validator_1.IsString)(),
        (0, class_validator_1.IsOptional)(),
        __metadata("design:type", String)
    ], StringComparisonOperator.prototype, "gt", void 0);
    __decorate([
        (0, class_validator_1.IsString)(),
        (0, class_validator_1.IsOptional)(),
        __metadata("design:type", String)
    ], StringComparisonOperator.prototype, "gte", void 0);
    __decorate([
        (0, class_validator_1.IsString)(),
        (0, class_validator_1.IsOptional)(),
        __metadata("design:type", String)
    ], StringComparisonOperator.prototype, "lte", void 0);
    return StringComparisonOperator;
}());
exports.StringComparisonOperator = StringComparisonOperator;
var NumericalComparisonOperator = /** @class */ (function () {
    function NumericalComparisonOperator() {
    }
    __decorate([
        (0, class_validator_1.IsNumber)(),
        (0, class_validator_1.IsOptional)(),
        (0, class_transformer_1.Type)(function () { return Number; }),
        __metadata("design:type", Number)
    ], NumericalComparisonOperator.prototype, "lt", void 0);
    __decorate([
        (0, class_validator_1.IsNumber)(),
        (0, class_validator_1.IsOptional)(),
        (0, class_transformer_1.Type)(function () { return Number; }),
        __metadata("design:type", Number)
    ], NumericalComparisonOperator.prototype, "gt", void 0);
    __decorate([
        (0, class_validator_1.IsNumber)(),
        (0, class_validator_1.IsOptional)(),
        (0, class_transformer_1.Type)(function () { return Number; }),
        __metadata("design:type", Number)
    ], NumericalComparisonOperator.prototype, "gte", void 0);
    __decorate([
        (0, class_validator_1.IsNumber)(),
        (0, class_validator_1.IsOptional)(),
        (0, class_transformer_1.Type)(function () { return Number; }),
        __metadata("design:type", Number)
    ], NumericalComparisonOperator.prototype, "lte", void 0);
    return NumericalComparisonOperator;
}());
exports.NumericalComparisonOperator = NumericalComparisonOperator;
var AddressPayload = /** @class */ (function () {
    function AddressPayload() {
    }
    __decorate([
        (0, class_validator_1.IsOptional)(),
        (0, class_validator_1.IsString)(),
        __metadata("design:type", String)
    ], AddressPayload.prototype, "first_name", void 0);
    __decorate([
        (0, class_validator_1.IsOptional)(),
        (0, class_validator_1.IsString)(),
        __metadata("design:type", String)
    ], AddressPayload.prototype, "last_name", void 0);
    __decorate([
        (0, class_validator_1.IsOptional)(),
        (0, class_validator_1.IsString)(),
        __metadata("design:type", String)
    ], AddressPayload.prototype, "phone", void 0);
    __decorate([
        (0, class_validator_1.IsOptional)(),
        (0, class_validator_1.IsObject)(),
        __metadata("design:type", Object)
    ], AddressPayload.prototype, "metadata", void 0);
    __decorate([
        (0, class_validator_1.IsOptional)(),
        (0, class_validator_1.IsString)(),
        __metadata("design:type", String)
    ], AddressPayload.prototype, "company", void 0);
    __decorate([
        (0, class_validator_1.IsOptional)(),
        (0, class_validator_1.IsString)(),
        __metadata("design:type", String)
    ], AddressPayload.prototype, "address_1", void 0);
    __decorate([
        (0, class_validator_1.IsOptional)(),
        (0, class_validator_1.IsString)(),
        __metadata("design:type", String)
    ], AddressPayload.prototype, "address_2", void 0);
    __decorate([
        (0, class_validator_1.IsOptional)(),
        (0, class_validator_1.IsString)(),
        __metadata("design:type", String)
    ], AddressPayload.prototype, "city", void 0);
    __decorate([
        (0, class_validator_1.IsOptional)(),
        (0, class_validator_1.IsString)(),
        __metadata("design:type", String)
    ], AddressPayload.prototype, "country_code", void 0);
    __decorate([
        (0, class_validator_1.IsOptional)(),
        (0, class_validator_1.IsString)(),
        __metadata("design:type", String)
    ], AddressPayload.prototype, "province", void 0);
    __decorate([
        (0, class_validator_1.IsOptional)(),
        (0, class_validator_1.IsString)(),
        __metadata("design:type", String)
    ], AddressPayload.prototype, "postal_code", void 0);
    return AddressPayload;
}());
exports.AddressPayload = AddressPayload;
var AddressCreatePayload = /** @class */ (function () {
    function AddressCreatePayload() {
    }
    __decorate([
        (0, class_validator_1.IsString)(),
        __metadata("design:type", String)
    ], AddressCreatePayload.prototype, "first_name", void 0);
    __decorate([
        (0, class_validator_1.IsString)(),
        __metadata("design:type", String)
    ], AddressCreatePayload.prototype, "last_name", void 0);
    __decorate([
        (0, class_validator_1.IsOptional)(),
        (0, class_validator_1.IsString)(),
        __metadata("design:type", String)
    ], AddressCreatePayload.prototype, "phone", void 0);
    __decorate([
        (0, class_validator_1.IsOptional)(),
        __metadata("design:type", Object)
    ], AddressCreatePayload.prototype, "metadata", void 0);
    __decorate([
        (0, class_validator_1.IsOptional)(),
        (0, class_validator_1.IsString)(),
        __metadata("design:type", String)
    ], AddressCreatePayload.prototype, "company", void 0);
    __decorate([
        (0, class_validator_1.IsString)(),
        __metadata("design:type", String)
    ], AddressCreatePayload.prototype, "address_1", void 0);
    __decorate([
        (0, class_validator_1.IsOptional)(),
        (0, class_validator_1.IsString)(),
        __metadata("design:type", String)
    ], AddressCreatePayload.prototype, "address_2", void 0);
    __decorate([
        (0, class_validator_1.IsString)(),
        __metadata("design:type", String)
    ], AddressCreatePayload.prototype, "city", void 0);
    __decorate([
        (0, class_validator_1.IsString)(),
        __metadata("design:type", String)
    ], AddressCreatePayload.prototype, "country_code", void 0);
    __decorate([
        (0, class_validator_1.IsOptional)(),
        (0, class_validator_1.IsString)(),
        __metadata("design:type", String)
    ], AddressCreatePayload.prototype, "province", void 0);
    __decorate([
        (0, class_validator_1.IsString)(),
        __metadata("design:type", String)
    ], AddressCreatePayload.prototype, "postal_code", void 0);
    return AddressCreatePayload;
}());
exports.AddressCreatePayload = AddressCreatePayload;
var FindParams = /** @class */ (function () {
    function FindParams() {
    }
    __decorate([
        (0, class_validator_1.IsString)(),
        (0, class_validator_1.IsOptional)(),
        __metadata("design:type", String)
    ], FindParams.prototype, "expand", void 0);
    __decorate([
        (0, class_validator_1.IsString)(),
        (0, class_validator_1.IsOptional)(),
        __metadata("design:type", String)
    ], FindParams.prototype, "fields", void 0);
    return FindParams;
}());
exports.FindParams = FindParams;
var FindPaginationParams = /** @class */ (function () {
    function FindPaginationParams() {
        this.offset = 0;
        this.limit = 20;
    }
    __decorate([
        (0, class_validator_1.IsNumber)(),
        (0, class_validator_1.IsOptional)(),
        (0, class_transformer_1.Type)(function () { return Number; }),
        __metadata("design:type", Number)
    ], FindPaginationParams.prototype, "offset", void 0);
    __decorate([
        (0, class_validator_1.IsNumber)(),
        (0, class_validator_1.IsOptional)(),
        (0, class_transformer_1.Type)(function () { return Number; }),
        __metadata("design:type", Number)
    ], FindPaginationParams.prototype, "limit", void 0);
    return FindPaginationParams;
}());
exports.FindPaginationParams = FindPaginationParams;
function extendedFindParamsMixin(_a) {
    var _b = _a === void 0 ? {} : _a, limit = _b.limit, offset = _b.offset;
    var FindExtendedPaginationParams = /** @class */ (function (_super) {
        __extends(FindExtendedPaginationParams, _super);
        function FindExtendedPaginationParams() {
            var _this = _super !== null && _super.apply(this, arguments) || this;
            _this.offset = offset !== null && offset !== void 0 ? offset : 0;
            _this.limit = limit !== null && limit !== void 0 ? limit : 20;
            return _this;
        }
        __decorate([
            (0, class_validator_1.IsNumber)(),
            (0, class_validator_1.IsOptional)(),
            (0, class_transformer_1.Type)(function () { return Number; }),
            __metadata("design:type", Number)
        ], FindExtendedPaginationParams.prototype, "offset", void 0);
        __decorate([
            (0, class_validator_1.IsNumber)(),
            (0, class_validator_1.IsOptional)(),
            (0, class_transformer_1.Type)(function () { return Number; }),
            __metadata("design:type", Number)
        ], FindExtendedPaginationParams.prototype, "limit", void 0);
        return FindExtendedPaginationParams;
    }(FindParams));
    return FindExtendedPaginationParams;
}
exports.extendedFindParamsMixin = extendedFindParamsMixin;
//# sourceMappingURL=common.js.map