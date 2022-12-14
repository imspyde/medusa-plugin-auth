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
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
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
exports.SalesChannelRepository = void 0;
var typeorm_1 = require("typeorm");
var models_1 = require("../models");
var lodash_1 = require("lodash");
var SalesChannelRepository = /** @class */ (function (_super) {
    __extends(SalesChannelRepository, _super);
    function SalesChannelRepository() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    SalesChannelRepository.prototype.findWithRelations = function (relations, idsOrOptionsWithoutRelations) {
        if (relations === void 0) { relations = []; }
        if (idsOrOptionsWithoutRelations === void 0) { idsOrOptionsWithoutRelations = {}; }
        return __awaiter(this, void 0, void 0, function () {
            var entities, count, _a, results, resultCount, entitiesIds, groupedRelations, relations_1, relations_1_1, rel, _b, topLevel, entitiesIdsWithRelations, entitiesAndRelations, entitiesAndRelationsById;
            var e_1, _c;
            var _this = this;
            return __generator(this, function (_d) {
                switch (_d.label) {
                    case 0:
                        entities = [];
                        count = 0;
                        if (!Array.isArray(idsOrOptionsWithoutRelations)) return [3 /*break*/, 2];
                        return [4 /*yield*/, this.findByIds(idsOrOptionsWithoutRelations)];
                    case 1:
                        entities = _d.sent();
                        count = idsOrOptionsWithoutRelations.length;
                        return [3 /*break*/, 4];
                    case 2: return [4 /*yield*/, this.findAndCount(idsOrOptionsWithoutRelations)];
                    case 3:
                        _a = __read.apply(void 0, [_d.sent(), 2]), results = _a[0], resultCount = _a[1];
                        entities = results;
                        count = resultCount;
                        _d.label = 4;
                    case 4:
                        entitiesIds = entities.map(function (_a) {
                            var id = _a.id;
                            return id;
                        });
                        groupedRelations = {};
                        try {
                            for (relations_1 = __values(relations), relations_1_1 = relations_1.next(); !relations_1_1.done; relations_1_1 = relations_1.next()) {
                                rel = relations_1_1.value;
                                _b = __read(rel.split("."), 1), topLevel = _b[0];
                                if (groupedRelations[topLevel]) {
                                    groupedRelations[topLevel].push(rel);
                                }
                                else {
                                    groupedRelations[topLevel] = [rel];
                                }
                            }
                        }
                        catch (e_1_1) { e_1 = { error: e_1_1 }; }
                        finally {
                            try {
                                if (relations_1_1 && !relations_1_1.done && (_c = relations_1.return)) _c.call(relations_1);
                            }
                            finally { if (e_1) throw e_1.error; }
                        }
                        return [4 /*yield*/, Promise.all(Object.entries(groupedRelations).map(function (_a) {
                                var _b = __read(_a, 2), _ = _b[0], rels = _b[1];
                                return __awaiter(_this, void 0, void 0, function () {
                                    return __generator(this, function (_c) {
                                        return [2 /*return*/, this.findByIds(entitiesIds, {
                                                select: ["id"],
                                                relations: rels,
                                            })];
                                    });
                                });
                            })).then(lodash_1.flatten)];
                    case 5:
                        entitiesIdsWithRelations = _d.sent();
                        entitiesAndRelations = entitiesIdsWithRelations.concat(entities);
                        entitiesAndRelationsById = (0, lodash_1.groupBy)(entitiesAndRelations, "id");
                        return [2 /*return*/, [
                                Object.values(entitiesAndRelationsById).map(function (v) { return lodash_1.merge.apply(void 0, __spreadArray([{}], __read(v), false)); }),
                                count,
                            ]];
                }
            });
        });
    };
    SalesChannelRepository.prototype.getFreeTextSearchResultsAndCount = function (q, options) {
        var _a, _b;
        if (options === void 0) { options = {
            where: {},
        }; }
        return __awaiter(this, void 0, void 0, function () {
            var options_, qb;
            return __generator(this, function (_c) {
                switch (_c.label) {
                    case 0:
                        options_ = __assign({}, options);
                        (_a = options_ === null || options_ === void 0 ? void 0 : options_.where) === null || _a === void 0 ? true : delete _a.name;
                        (_b = options_ === null || options_ === void 0 ? void 0 : options_.where) === null || _b === void 0 ? true : delete _b.description;
                        qb = this.createQueryBuilder("sales_channel")
                            .select()
                            .where(options_.where)
                            .andWhere(new typeorm_1.Brackets(function (qb) {
                            qb.where("sales_channel.description ILIKE :q", {
                                q: "%".concat(q, "%"),
                            }).orWhere("sales_channel.name ILIKE :q", { q: "%".concat(q, "%") });
                        }))
                            .skip(options.skip)
                            .take(options.take);
                        if (options.withDeleted) {
                            qb = qb.withDeleted();
                        }
                        return [4 /*yield*/, qb.getManyAndCount()];
                    case 1: return [2 /*return*/, _c.sent()];
                }
            });
        });
    };
    SalesChannelRepository.prototype.removeProducts = function (salesChannelId, productIds) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.createQueryBuilder()
                            .delete()
                            .from("product_sales_channel")
                            .where({
                            sales_channel_id: salesChannelId,
                            product_id: (0, typeorm_1.In)(productIds),
                        })
                            .execute()];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    SalesChannelRepository.prototype.addProducts = function (salesChannelId, productIds) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.createQueryBuilder()
                            .insert()
                            .into("product_sales_channel")
                            .values(productIds.map(function (id) { return ({
                            sales_channel_id: salesChannelId,
                            product_id: id,
                        }); }))
                            .orIgnore()
                            .execute()];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    SalesChannelRepository.prototype.findOneWithRelations = function (relations, optionsWithoutRelations) {
        if (relations === void 0) { relations = []; }
        if (optionsWithoutRelations === void 0) { optionsWithoutRelations = {}; }
        return __awaiter(this, void 0, void 0, function () {
            var _a, result;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        // Limit 1
                        optionsWithoutRelations.take = 1;
                        return [4 /*yield*/, this.findWithRelations(relations, optionsWithoutRelations)];
                    case 1:
                        _a = __read.apply(void 0, [_b.sent(), 1]), result = _a[0];
                        return [2 /*return*/, result[0]];
                }
            });
        });
    };
    SalesChannelRepository = __decorate([
        (0, typeorm_1.EntityRepository)(models_1.SalesChannel)
    ], SalesChannelRepository);
    return SalesChannelRepository;
}(typeorm_1.Repository));
exports.SalesChannelRepository = SalesChannelRepository;
//# sourceMappingURL=sales-channel.js.map