import "reflect-metadata";
import { SalesChannel } from "../../../../models";
import { DeleteResponse, PaginatedResponse } from "../../../../types/common";
declare const _default: (app: any) => any;
export default _default;
export declare type AdminSalesChannelsRes = {
    sales_channel: SalesChannel;
};
export declare type AdminSalesChannelsDeleteRes = DeleteResponse;
export declare type AdminSalesChannelsListRes = PaginatedResponse & {
    sales_channels: SalesChannel[];
};
export * from "./add-product-batch";
export * from "./create-sales-channel";
export * from "./delete-products-batch";
export * from "./delete-sales-channel";
export * from "./get-sales-channel";
export * from "./list-sales-channels";
export * from "./update-sales-channel";
