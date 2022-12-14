import { EntityManager } from "typeorm";
import { AbstractSearchService } from "../interfaces/search-service";
import { Logger } from "../types/global";
declare type InjectedDependencies = {
    logger: Logger;
    manager: EntityManager;
};
export default class DefaultSearchService extends AbstractSearchService {
    isDefault: boolean;
    protected manager_: EntityManager;
    protected transactionManager_: EntityManager | undefined;
    protected readonly logger_: Logger;
    protected readonly options_: Record<string, unknown>;
    constructor({ logger, manager }: InjectedDependencies, options: any);
    createIndex(indexName: string, options: unknown): Promise<void>;
    getIndex(indexName: string): Promise<void>;
    addDocuments(indexName: string, documents: unknown, type: string): Promise<void>;
    replaceDocuments(indexName: string, documents: unknown, type: string): Promise<void>;
    deleteDocument(indexName: string, document_id: string | number): Promise<void>;
    deleteAllDocuments(indexName: string): Promise<void>;
    search(indexName: string, query: unknown, options: unknown): Promise<{
        hits: unknown[];
    }>;
    updateSettings(indexName: string, settings: unknown): Promise<void>;
}
export {};
