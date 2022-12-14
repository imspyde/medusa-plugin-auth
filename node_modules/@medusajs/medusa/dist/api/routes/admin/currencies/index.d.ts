import { Currency } from "../../../..";
import { PaginatedResponse } from "../../../../types/common";
declare const _default: (app: any) => any;
export default _default;
export declare type AdminCurrenciesListRes = PaginatedResponse & {
    currencies: Currency[];
};
export declare type AdminCurrenciesRes = {
    currency: Currency;
};
export * from "./list-currencies";
export * from "./update-currency";
