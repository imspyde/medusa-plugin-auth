"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.AdminPostOrdersOrderClaimsClaimReq = void 0;
var class_validator_1 = require("class-validator");
var _1 = require(".");
var class_transformer_1 = require("class-transformer");
var validator_1 = require("../../../../utils/validator");
/**
 * @oas [post] /order/{id}/claims/{claim_id}
 * operationId: "PostOrdersOrderClaimsClaim"
 * summary: "Update a Claim"
 * description: "Updates a Claim."
 * x-authenticated: true
 * parameters:
 *   - (path) id=* {string} The ID of the Order.
 *   - (path) claim_id=* {string} The ID of the Claim.
 * requestBody:
 *   content:
 *     application/json:
 *       schema:
 *         properties:
 *           claim_items:
 *             description: The Claim Items that the Claim will consist of.
 *             type: array
 *             items:
 *               required:
 *                 - id
 *                 - images
 *                 - tags
 *               properties:
 *                 id:
 *                   description: The ID of the Claim Item.
 *                   type: string
 *                 item_id:
 *                   description: The ID of the Line Item that will be claimed.
 *                   type: string
 *                 quantity:
 *                   description: The number of items that will be returned
 *                   type: integer
 *                 note:
 *                   description: Short text describing the Claim Item in further detail.
 *                   type: string
 *                 reason:
 *                   description: The reason for the Claim
 *                   type: string
 *                   enum:
 *                     - missing_item
 *                     - wrong_item
 *                     - production_failure
 *                     - other
 *                 tags:
 *                   description: A list o tags to add to the Claim Item
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                         description: Tag ID
 *                       value:
 *                         type: string
 *                         description: Tag value
 *                 images:
 *                   description: A list of image URL's that will be associated with the Claim
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                         description: Image ID
 *                       url:
 *                         type: string
 *                         description: Image URL
 *                 metadata:
 *                   description: An optional set of key-value pairs to hold additional information.
 *                   type: object
 *           shipping_methods:
 *             description: The Shipping Methods to send the additional Line Items with.
 *             type: array
 *             items:
 *                properties:
 *                  id:
 *                    description: The ID of an existing Shipping Method
 *                    type: string
 *                  option_id:
 *                    description: The ID of the Shipping Option to create a Shipping Method from
 *                    type: string
 *                  price:
 *                    description: The price to charge for the Shipping Method
 *                    type: integer
 *           no_notification:
 *             description: If set to true no notification will be send related to this Swap.
 *             type: boolean
 *           metadata:
 *             description: An optional set of key-value pairs to hold additional information.
 *             type: object
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       // must be previously logged in or use api token
 *       medusa.admin.orders.updateClaim(order_id, claim_id, {
 *         no_notification: true
 *       })
 *       .then(({ order }) => {
 *         console.log(order.id);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/admin/orders/{id}/claims/{claim_id}' \
 *       --header 'Authorization: Bearer {api_token}' \
 *       --header 'Content-Type: application/json' \
 *       --data-raw '{
 *           "no_notification": true
 *       }'
 * security:
 *   - api_token: []
 *   - cookie_auth: []
 * tags:
 *   - Claim
 * responses:
 *   200:
 *     description: OK
 *     content:
 *       application/json:
 *         schema:
 *           properties:
 *             order:
 *               $ref: "#/components/schemas/order"
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
    var _a, id, claim_id, validated, orderService, claimService, manager, data;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                _a = req.params, id = _a.id, claim_id = _a.claim_id;
                return [4 /*yield*/, (0, validator_1.validator)(AdminPostOrdersOrderClaimsClaimReq, req.body)];
            case 1:
                validated = _b.sent();
                orderService = req.scope.resolve("orderService");
                claimService = req.scope.resolve("claimService");
                manager = req.scope.resolve("manager");
                return [4 /*yield*/, manager.transaction(function (transactionManager) { return __awaiter(void 0, void 0, void 0, function () {
                        return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0: return [4 /*yield*/, claimService
                                        .withTransaction(transactionManager)
                                        .update(claim_id, validated)];
                                case 1: return [2 /*return*/, _a.sent()];
                            }
                        });
                    }); })];
            case 2:
                _b.sent();
                return [4 /*yield*/, orderService.retrieve(id, {
                        select: _1.defaultAdminOrdersFields,
                        relations: _1.defaultAdminOrdersRelations,
                    })];
            case 3:
                data = _b.sent();
                res.json({ order: data });
                return [2 /*return*/];
        }
    });
}); });
var AdminPostOrdersOrderClaimsClaimReq = /** @class */ (function () {
    function AdminPostOrdersOrderClaimsClaimReq() {
    }
    __decorate([
        (0, class_validator_1.IsArray)(),
        (0, class_validator_1.IsOptional)(),
        (0, class_transformer_1.Type)(function () { return Item; }),
        (0, class_validator_1.ValidateNested)({ each: true }),
        __metadata("design:type", Array)
    ], AdminPostOrdersOrderClaimsClaimReq.prototype, "claim_items", void 0);
    __decorate([
        (0, class_validator_1.IsArray)(),
        (0, class_validator_1.IsOptional)(),
        (0, class_validator_1.ValidateNested)({ each: true }),
        (0, class_transformer_1.Type)(function () { return ShippingMethod; }),
        __metadata("design:type", Array)
    ], AdminPostOrdersOrderClaimsClaimReq.prototype, "shipping_methods", void 0);
    __decorate([
        (0, class_validator_1.IsBoolean)(),
        (0, class_validator_1.IsOptional)(),
        __metadata("design:type", Boolean)
    ], AdminPostOrdersOrderClaimsClaimReq.prototype, "no_notification", void 0);
    __decorate([
        (0, class_validator_1.IsObject)(),
        (0, class_validator_1.IsOptional)(),
        __metadata("design:type", Object)
    ], AdminPostOrdersOrderClaimsClaimReq.prototype, "metadata", void 0);
    return AdminPostOrdersOrderClaimsClaimReq;
}());
exports.AdminPostOrdersOrderClaimsClaimReq = AdminPostOrdersOrderClaimsClaimReq;
var ShippingMethod = /** @class */ (function () {
    function ShippingMethod() {
    }
    __decorate([
        (0, class_validator_1.IsString)(),
        (0, class_validator_1.IsOptional)(),
        __metadata("design:type", String)
    ], ShippingMethod.prototype, "id", void 0);
    __decorate([
        (0, class_validator_1.IsString)(),
        (0, class_validator_1.IsOptional)(),
        __metadata("design:type", String)
    ], ShippingMethod.prototype, "option_id", void 0);
    __decorate([
        (0, class_validator_1.IsInt)(),
        (0, class_validator_1.IsOptional)(),
        __metadata("design:type", Number)
    ], ShippingMethod.prototype, "price", void 0);
    return ShippingMethod;
}());
var Item = /** @class */ (function () {
    function Item() {
    }
    __decorate([
        (0, class_validator_1.IsString)(),
        (0, class_validator_1.IsNotEmpty)(),
        __metadata("design:type", String)
    ], Item.prototype, "id", void 0);
    __decorate([
        (0, class_validator_1.IsString)(),
        (0, class_validator_1.IsOptional)(),
        __metadata("design:type", String)
    ], Item.prototype, "note", void 0);
    __decorate([
        (0, class_validator_1.IsString)(),
        (0, class_validator_1.IsOptional)(),
        __metadata("design:type", String)
    ], Item.prototype, "reason", void 0);
    __decorate([
        (0, class_validator_1.IsArray)(),
        (0, class_validator_1.ValidateNested)({ each: true }),
        (0, class_transformer_1.Type)(function () { return Image; }),
        __metadata("design:type", Array)
    ], Item.prototype, "images", void 0);
    __decorate([
        (0, class_validator_1.IsArray)(),
        (0, class_validator_1.ValidateNested)({ each: true }),
        (0, class_transformer_1.Type)(function () { return Tag; }),
        __metadata("design:type", Array)
    ], Item.prototype, "tags", void 0);
    __decorate([
        (0, class_validator_1.IsObject)(),
        (0, class_validator_1.IsOptional)(),
        __metadata("design:type", Object)
    ], Item.prototype, "metadata", void 0);
    return Item;
}());
var Image = /** @class */ (function () {
    function Image() {
    }
    __decorate([
        (0, class_validator_1.IsString)(),
        (0, class_validator_1.IsOptional)(),
        __metadata("design:type", String)
    ], Image.prototype, "id", void 0);
    __decorate([
        (0, class_validator_1.IsString)(),
        (0, class_validator_1.IsOptional)(),
        __metadata("design:type", String)
    ], Image.prototype, "url", void 0);
    return Image;
}());
var Tag = /** @class */ (function () {
    function Tag() {
    }
    __decorate([
        (0, class_validator_1.IsString)(),
        (0, class_validator_1.IsOptional)(),
        __metadata("design:type", String)
    ], Tag.prototype, "id", void 0);
    __decorate([
        (0, class_validator_1.IsString)(),
        (0, class_validator_1.IsOptional)(),
        __metadata("design:type", String)
    ], Tag.prototype, "value", void 0);
    return Tag;
}());
//# sourceMappingURL=update-claim.js.map