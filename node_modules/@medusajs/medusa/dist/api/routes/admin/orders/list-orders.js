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
var __spreadArray = (this && this.__spreadArray) || function (to, from, pack) {
    if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
        if (ar || !(i in from)) {
            if (!ar) ar = Array.prototype.slice.call(from, 0, i);
            ar[i] = from[i];
        }
    }
    return to.concat(ar || Array.prototype.slice.call(from));
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AdminGetOrdersParams = void 0;
var class_validator_1 = require("class-validator");
var orders_1 = require("../../../../types/orders");
var class_transformer_1 = require("class-transformer");
var lodash_1 = require("lodash");
/**
 * @oas [get] /orders
 * operationId: "GetOrders"
 * summary: "List Orders"
 * description: "Retrieves a list of Orders"
 * x-authenticated: true
 * parameters:
 *   - (query) q {string} Query used for searching orders by shipping address first name, orders' email, and orders' display ID
 *   - (query) id {string} ID of the order to search for.
 *   - in: query
 *     name: status
 *     style: form
 *     explode: false
 *     description: Status to search for
 *     schema:
 *       type: array
 *       items:
 *         type: string
 *         enum: [pending, completed, archived, canceled, requires_action]
 *   - in: query
 *     name: fulfillment_status
 *     style: form
 *     explode: false
 *     description: Fulfillment status to search for.
 *     schema:
 *       type: array
 *       items:
 *         type: string
 *         enum: [not_fulfilled, fulfilled, partially_fulfilled, shipped, partially_shipped, canceled, returned, partially_returned, requires_action]
 *   - in: query
 *     name: payment_status
 *     style: form
 *     explode: false
 *     description: Payment status to search for.
 *     schema:
 *       type: array
 *       items:
 *         type: string
 *         enum: [captured, awaiting, not_paid, refunded, partially_refunded, canceled, requires_action]
 *   - (query) display_id {string} Display ID to search for.
 *   - (query) cart_id {string} to search for.
 *   - (query) customer_id {string} to search for.
 *   - (query) email {string} to search for.
 *   - in: query
 *     name: region_id
 *     style: form
 *     explode: false
 *     description: Regions to search orders by
 *     schema:
 *       oneOf:
 *         - type: string
 *           description: ID of a Region.
 *         - type: array
 *           items:
 *             type: string
 *             description: ID of a Region.
 *   - in: query
 *     name: currency_code
 *     style: form
 *     explode: false
 *     description: Currency code to search for
 *     schema:
 *       type: string
 *       externalDocs:
 *         url: https://en.wikipedia.org/wiki/ISO_4217#Active_codes
 *         description: See a list of codes.
 *   - (query) tax_rate {string} to search for.
 *   - in: query
 *     name: created_at
 *     description: Date comparison for when resulting orders were created.
 *     schema:
 *       type: object
 *       properties:
 *         lt:
 *            type: string
 *            description: filter by dates less than this date
 *            format: date
 *         gt:
 *            type: string
 *            description: filter by dates greater than this date
 *            format: date
 *         lte:
 *            type: string
 *            description: filter by dates less than or equal to this date
 *            format: date
 *         gte:
 *            type: string
 *            description: filter by dates greater than or equal to this date
 *            format: date
 *   - in: query
 *     name: updated_at
 *     description: Date comparison for when resulting orders were updated.
 *     schema:
 *       type: object
 *       properties:
 *         lt:
 *            type: string
 *            description: filter by dates less than this date
 *            format: date
 *         gt:
 *            type: string
 *            description: filter by dates greater than this date
 *            format: date
 *         lte:
 *            type: string
 *            description: filter by dates less than or equal to this date
 *            format: date
 *         gte:
 *            type: string
 *            description: filter by dates greater than or equal to this date
 *            format: date
 *   - in: query
 *     name: canceled_at
 *     description: Date comparison for when resulting orders were canceled.
 *     schema:
 *       type: object
 *       properties:
 *         lt:
 *            type: string
 *            description: filter by dates less than this date
 *            format: date
 *         gt:
 *            type: string
 *            description: filter by dates greater than this date
 *            format: date
 *         lte:
 *            type: string
 *            description: filter by dates less than or equal to this date
 *            format: date
 *         gte:
 *            type: string
 *            description: filter by dates greater than or equal to this date
 *            format: date
 *   - in: query
 *     name: sales_channel_id
 *     style: form
 *     explode: false
 *     description: Filter by Sales Channels
 *     schema:
 *       type: array
 *       items:
 *         type: string
 *         description: The ID of a Sales Channel
 *   - (query) offset=0 {integer} How many orders to skip before the results.
 *   - (query) limit=50 {integer} Limit the number of orders returned.
 *   - (query) expand {string} (Comma separated) Which fields should be expanded in each order of the result.
 *   - (query) fields {string} (Comma separated) Which fields should be included in each order of the result.
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       // must be previously logged in or use api token
 *       medusa.admin.orders.list()
 *       .then(({ orders, limit, offset, count }) => {
 *         console.log(orders.length);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request GET 'https://medusa-url.com/admin/orders' \
 *       --header 'Authorization: Bearer {api_token}'
 * security:
 *   - api_token: []
 *   - cookie_auth: []
 * tags:
 *   - Order
 * responses:
 *   200:
 *     description: OK
 *     content:
 *       application/json:
 *         schema:
 *           properties:
 *             orders:
 *               type: array
 *               items:
 *                 $ref: "#/components/schemas/order"
 *             count:
 *               type: integer
 *               description: The total number of items available
 *             offset:
 *               type: integer
 *               description: The number of items skipped before these items
 *             limit:
 *               type: integer
 *               description: The number of items per page
 *   "400":
 *     $ref: "#/components/responses/400_error"
 *   "401":
 *     $ref: "#/components/responses/unauthorized"
 *   "404":
 *     $ref: "#/components/responses/not_found_error"
 *   "409":
 *     $ref: "#/components/responses/invalid_state_error"
 *   "422":
 *     $ref: "#/components/responses/invalid_request_error"
 *   "500":
 *     $ref: "#/components/responses/500_error"
 */
exports.default = (function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var orderService, _a, skip, take, select, relations, _b, orders, count, data, fields;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                orderService = req.scope.resolve("orderService");
                _a = req.listConfig, skip = _a.skip, take = _a.take, select = _a.select, relations = _a.relations;
                return [4 /*yield*/, orderService.listAndCount(req.filterableFields, req.listConfig)];
            case 1:
                _b = __read.apply(void 0, [_c.sent(), 2]), orders = _b[0], count = _b[1];
                data = orders;
                fields = __spreadArray(__spreadArray([], __read(select), false), __read(relations), false);
                if (fields.length) {
                    data = orders.map(function (o) { return (0, lodash_1.pick)(o, fields); });
                }
                res.json({ orders: data, count: count, offset: skip, limit: take });
                return [2 /*return*/];
        }
    });
}); });
var AdminGetOrdersParams = /** @class */ (function (_super) {
    __extends(AdminGetOrdersParams, _super);
    function AdminGetOrdersParams() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        _this.offset = 0;
        _this.limit = 50;
        return _this;
    }
    __decorate([
        (0, class_validator_1.IsNumber)(),
        (0, class_validator_1.IsOptional)(),
        (0, class_transformer_1.Type)(function () { return Number; }),
        __metadata("design:type", Object)
    ], AdminGetOrdersParams.prototype, "offset", void 0);
    __decorate([
        (0, class_validator_1.IsNumber)(),
        (0, class_validator_1.IsOptional)(),
        (0, class_transformer_1.Type)(function () { return Number; }),
        __metadata("design:type", Object)
    ], AdminGetOrdersParams.prototype, "limit", void 0);
    __decorate([
        (0, class_validator_1.IsString)(),
        (0, class_validator_1.IsOptional)(),
        __metadata("design:type", String)
    ], AdminGetOrdersParams.prototype, "expand", void 0);
    __decorate([
        (0, class_validator_1.IsString)(),
        (0, class_validator_1.IsOptional)(),
        __metadata("design:type", String)
    ], AdminGetOrdersParams.prototype, "fields", void 0);
    return AdminGetOrdersParams;
}(orders_1.AdminListOrdersSelector));
exports.AdminGetOrdersParams = AdminGetOrdersParams;
//# sourceMappingURL=list-orders.js.map