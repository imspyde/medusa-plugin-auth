import "reflect-metadata";
import { PriceList } from "../../../..";
import { DeleteResponse, PaginatedResponse } from "../../../../types/common";
import { FlagRouter } from "../../../../utils/flag-router";
declare const _default: (app: any, featureFlagRouter: FlagRouter) => any;
export default _default;
export declare const defaultAdminPriceListFields: string[];
export declare const defaultAdminPriceListRelations: string[];
export declare const allowedAdminPriceListFields: string[];
export declare type AdminPriceListRes = {
    price_list: PriceList;
};
export declare type AdminPriceListDeleteBatchRes = {
    ids: string[];
    deleted: boolean;
    object: string;
};
export declare type AdminPriceListDeleteProductPricesRes = AdminPriceListDeleteBatchRes;
export declare type AdminPriceListDeleteVariantPricesRes = AdminPriceListDeleteBatchRes;
export declare type AdminPriceListDeleteRes = DeleteResponse;
export declare type AdminPriceListsListRes = PaginatedResponse & {
    price_lists: PriceList[];
};
export * from "./add-prices-batch";
export * from "./create-price-list";
export * from "./delete-price-list";
export * from "./get-price-list";
export * from "./list-price-lists";
export * from "./update-price-list";
export * from "./delete-prices-batch";
export * from "./list-price-list-products";
