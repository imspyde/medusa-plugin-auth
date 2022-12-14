import { DeleteResult, FindManyOptions, Repository } from "typeorm";
import { SalesChannel } from "../models";
import { ExtendedFindConfig, Selector } from "../types/common";
export declare class SalesChannelRepository extends Repository<SalesChannel> {
    findWithRelations(relations?: (keyof SalesChannel | string)[], idsOrOptionsWithoutRelations?: Omit<FindManyOptions<SalesChannel>, "relations"> | string[]): Promise<[SalesChannel[], number]>;
    getFreeTextSearchResultsAndCount(q: string, options?: ExtendedFindConfig<SalesChannel, Selector<SalesChannel>>): Promise<[SalesChannel[], number]>;
    removeProducts(salesChannelId: string, productIds: string[]): Promise<DeleteResult>;
    addProducts(salesChannelId: string, productIds: string[]): Promise<void>;
    findOneWithRelations(relations?: Array<keyof SalesChannel>, optionsWithoutRelations?: Omit<FindManyOptions<SalesChannel>, "relations">): Promise<SalesChannel>;
}
