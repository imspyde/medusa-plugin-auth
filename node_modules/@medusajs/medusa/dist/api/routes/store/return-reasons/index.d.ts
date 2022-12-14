import { ReturnReason } from "./../../../../";
declare const _default: (app: any) => any;
export default _default;
export declare const defaultStoreReturnReasonFields: (keyof ReturnReason)[];
export declare const defaultStoreReturnReasonRelations: (keyof ReturnReason)[];
export declare type StoreReturnReasonsListRes = {
    return_reasons: ReturnReason[];
};
export declare type StoreReturnReasonsRes = {
    return_reason: ReturnReason;
};
export * from "./get-reason";
