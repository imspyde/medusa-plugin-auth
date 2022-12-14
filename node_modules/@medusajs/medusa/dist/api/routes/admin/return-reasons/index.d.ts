import { ReturnReason } from "../../../..";
import { DeleteResponse } from "../../../../types/common";
declare const _default: (app: any) => any;
export default _default;
export declare const defaultAdminReturnReasonsFields: (keyof ReturnReason)[];
export declare const defaultAdminReturnReasonsRelations: (keyof ReturnReason)[];
export declare type AdminReturnReasonsRes = {
    return_reason: ReturnReason;
};
export declare type AdminReturnReasonsListRes = {
    return_reasons: ReturnReason[];
};
export declare type AdminReturnReasonsDeleteRes = DeleteResponse;
export * from "./create-reason";
export * from "./update-reason";
