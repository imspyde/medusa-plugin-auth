import EventBusService from "../services/event-bus";
import ProductService from "../services/product";
import { Product } from "../models";
import { ISearchService } from "../interfaces";
declare type InjectedDependencies = {
    eventBusService: EventBusService;
    searchService: ISearchService;
    productService: ProductService;
};
declare class SearchIndexingSubscriber {
    private readonly eventBusService_;
    private readonly searchService_;
    private readonly productService_;
    constructor({ eventBusService, searchService, productService, }: InjectedDependencies);
    indexDocuments: () => Promise<void>;
    protected retrieveNextProducts(lastSeenId: string, take: number): Promise<Product[]>;
}
export default SearchIndexingSubscriber;
