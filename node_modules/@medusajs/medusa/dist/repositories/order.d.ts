import { FindManyOptions, Repository } from "typeorm";
import { Order } from "../models";
export declare class OrderRepository extends Repository<Order> {
    findWithRelations(relations?: string[], optionsWithoutRelations?: Omit<FindManyOptions<Order>, "relations">): Promise<Order[]>;
    findOneWithRelations(relations?: string[], optionsWithoutRelations?: Omit<FindManyOptions<Order>, "relations">): Promise<Order>;
}
