import { Repository } from "typeorm";
import { ProductCollection } from "../models";
import { ExtendedFindConfig, Selector } from "../types/common";
export declare class ProductCollectionRepository extends Repository<ProductCollection> {
    findAndCountByDiscountConditionId(conditionId: string, query: ExtendedFindConfig<ProductCollection, Selector<ProductCollection>>): Promise<[ProductCollection[], number]>;
}
