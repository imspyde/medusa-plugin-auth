import { Repository } from "typeorm";
import { ProductTag } from "../models/product-tag";
import { ExtendedFindConfig, Selector } from "../types/common";
declare type UpsertTagsInput = (Partial<ProductTag> & {
    value: string;
})[];
declare type ProductTagSelector = Partial<ProductTag> & {
    q?: string;
    discount_condition_id?: string;
};
export declare type DefaultWithoutRelations = Omit<ExtendedFindConfig<ProductTag, ProductTagSelector>, "relations">;
export declare type FindWithoutRelationsOptions = DefaultWithoutRelations & {
    where: DefaultWithoutRelations["where"] & {
        discount_condition_id?: string;
    };
};
export declare class ProductTagRepository extends Repository<ProductTag> {
    listTagsByUsage(count?: number): Promise<ProductTag[]>;
    upsertTags(tags: UpsertTagsInput): Promise<ProductTag[]>;
    findAndCountByDiscountConditionId(conditionId: string, query: ExtendedFindConfig<ProductTag, Selector<ProductTag>>): Promise<[ProductTag[], number]>;
}
export {};
