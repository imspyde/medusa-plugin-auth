import { OrderEdit } from "../../../../models";
declare const _default: (app: any) => any;
export default _default;
export declare type StoreOrderEditsRes = {
    order_edit: Omit<OrderEdit, "internal_note" | "created_by" | "confirmed_by" | "canceled_by">;
};
export * from "./decline-order-edit";
