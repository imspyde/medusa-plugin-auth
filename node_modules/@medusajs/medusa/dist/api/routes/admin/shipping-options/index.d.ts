import { ShippingOption } from "../../../..";
import { PaginatedResponse, DeleteResponse } from "../../../../types/common";
import { FlagRouter } from "../../../../utils/flag-router";
declare const _default: (app: any, featureFlagRouter: FlagRouter) => any;
export default _default;
export declare const defaultFields: string[];
export declare const defaultRelations: string[];
export declare type AdminShippingOptionsListRes = PaginatedResponse & {
    shipping_options: ShippingOption[];
};
export declare type AdminShippingOptionsRes = {
    shipping_option: ShippingOption;
};
export declare type AdminShippingOptionsDeleteRes = DeleteResponse;
export * from "./create-shipping-option";
export * from "./delete-shipping-option";
export * from "./get-shipping-option";
export * from "./list-shipping-options";
export * from "./update-shipping-option";
