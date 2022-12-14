import { Repository } from "typeorm";
import { ProductType } from "../models/product-type";
import { ExtendedFindConfig, Selector } from "../types/common";
declare type UpsertTypeInput = Partial<ProductType> & {
    value: string;
};
export declare class ProductTypeRepository extends Repository<ProductType> {
    upsertType(type?: UpsertTypeInput): Promise<ProductType | null>;
    findAndCountByDiscountConditionId(conditionId: string, query: ExtendedFindConfig<ProductType, Selector<ProductType>>): Promise<[ProductType[], number]>;
}
export {};
