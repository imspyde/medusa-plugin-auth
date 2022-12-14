import { TransactionBaseService } from "../interfaces";
import { OrderItemChangeRepository } from "../repositories/order-item-change";
import { EntityManager } from "typeorm";
import { EventBusService, LineItemService } from "./index";
import { FindConfig, Selector } from "../types/common";
import { OrderItemChange } from "../models";
import TaxProviderService from "./tax-provider";
import { CreateOrderEditItemChangeInput } from "../types/order-edit";
declare type InjectedDependencies = {
    manager: EntityManager;
    orderItemChangeRepository: typeof OrderItemChangeRepository;
    eventBusService: EventBusService;
    lineItemService: LineItemService;
    taxProviderService: TaxProviderService;
};
export default class OrderEditItemChangeService extends TransactionBaseService {
    static readonly Events: {
        CREATED: string;
        DELETED: string;
    };
    protected manager_: EntityManager;
    protected transactionManager_: EntityManager | undefined;
    protected readonly orderItemChangeRepository_: typeof OrderItemChangeRepository;
    protected readonly eventBus_: EventBusService;
    protected readonly lineItemService_: LineItemService;
    protected readonly taxProviderService_: TaxProviderService;
    constructor({ manager, orderItemChangeRepository, eventBusService, lineItemService, taxProviderService, }: InjectedDependencies);
    retrieve(id: string, config?: FindConfig<OrderItemChange>): Promise<OrderItemChange | never>;
    list(selector: Selector<OrderItemChange>, config?: FindConfig<OrderItemChange>): Promise<OrderItemChange[]>;
    create(data: CreateOrderEditItemChangeInput): Promise<OrderItemChange>;
    delete(itemChangeIds: string | string[]): Promise<void>;
}
export {};
