import { DeleteResult, FindOperator, Repository } from "typeorm";
import { CustomerGroup } from "../models";
import { ExtendedFindConfig, Selector } from "../types/common";
export declare type DefaultWithoutRelations = Omit<ExtendedFindConfig<CustomerGroup, Selector<CustomerGroup>>, "relations">;
export declare type FindWithoutRelationsOptions = DefaultWithoutRelations & {
    where: DefaultWithoutRelations["where"] & {
        discount_condition_id?: string | FindOperator<string>;
    };
};
export declare class CustomerGroupRepository extends Repository<CustomerGroup> {
    addCustomers(groupId: string, customerIds: string[]): Promise<CustomerGroup>;
    removeCustomers(groupId: string, customerIds: string[]): Promise<DeleteResult>;
    findWithRelationsAndCount(relations?: string[], idsOrOptionsWithoutRelations?: FindWithoutRelationsOptions): Promise<[CustomerGroup[], number]>;
}
