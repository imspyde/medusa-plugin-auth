import { Swap } from "./../../../../";
import { FindConfig } from "../../../../types/common";
declare const _default: (app: any) => any;
export default _default;
export declare const defaultStoreSwapRelations: string[];
export declare const defaultStoreSwapFields: FindConfig<Swap>["select"];
export declare type StoreSwapsRes = {
    swap: Swap;
};
export * from "./create-swap";
export * from "./get-swap-by-cart";
