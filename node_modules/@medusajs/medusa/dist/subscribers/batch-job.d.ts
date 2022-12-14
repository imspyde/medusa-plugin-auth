import BatchJobService from "../services/batch-job";
import EventBusService from "../services/event-bus";
import { StrategyResolverService } from "../services";
import { EntityManager } from "typeorm";
declare type InjectedDependencies = {
    eventBusService: EventBusService;
    batchJobService: BatchJobService;
    strategyResolverService: StrategyResolverService;
    manager: EntityManager;
};
declare class BatchJobSubscriber {
    private readonly eventBusService_;
    private readonly batchJobService_;
    private readonly strategyResolver_;
    private readonly manager_;
    constructor({ eventBusService, batchJobService, strategyResolverService, manager, }: InjectedDependencies);
    preProcessBatchJob: (data: any) => Promise<void>;
    processBatchJob: (data: any) => Promise<void>;
}
export default BatchJobSubscriber;
