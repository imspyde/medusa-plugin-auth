import { EntityManager, SelectQueryBuilder } from "typeorm";
import { IPriceSelectionStrategy, PriceSelectionContext, TransactionBaseService } from "../interfaces";
import { MoneyAmount, Product, ProductOptionValue, ProductVariant } from "../models";
import { CartRepository } from "../repositories/cart";
import { MoneyAmountRepository } from "../repositories/money-amount";
import { ProductRepository } from "../repositories/product";
import { ProductOptionValueRepository } from "../repositories/product-option-value";
import { FindWithRelationsOptions, ProductVariantRepository } from "../repositories/product-variant";
import EventBusService from "./event-bus";
import RegionService from "./region";
import { FindConfig } from "../types/common";
import { CreateProductVariantInput, FilterableProductVariantProps, GetRegionPriceContext, ProductVariantPrice, UpdateProductVariantInput } from "../types/product-variant";
declare class ProductVariantService extends TransactionBaseService {
    static Events: {
        UPDATED: string;
        CREATED: string;
        DELETED: string;
    };
    protected manager_: EntityManager;
    protected transactionManager_: EntityManager | undefined;
    protected readonly productVariantRepository_: typeof ProductVariantRepository;
    protected readonly productRepository_: typeof ProductRepository;
    protected readonly eventBus_: EventBusService;
    protected readonly regionService_: RegionService;
    protected readonly priceSelectionStrategy_: IPriceSelectionStrategy;
    protected readonly moneyAmountRepository_: typeof MoneyAmountRepository;
    protected readonly productOptionValueRepository_: typeof ProductOptionValueRepository;
    protected readonly cartRepository_: typeof CartRepository;
    constructor({ manager, productVariantRepository, productRepository, eventBusService, regionService, moneyAmountRepository, productOptionValueRepository, cartRepository, priceSelectionStrategy, }: {
        manager: any;
        productVariantRepository: any;
        productRepository: any;
        eventBusService: any;
        regionService: any;
        moneyAmountRepository: any;
        productOptionValueRepository: any;
        cartRepository: any;
        priceSelectionStrategy: any;
    });
    /**
     * Gets a product variant by id.
     * @param variantId - the id of the product to get.
     * @param config - query config object for variant retrieval.
     * @return the product document.
     */
    retrieve(variantId: string, config?: FindConfig<ProductVariant> & PriceSelectionContext): Promise<ProductVariant>;
    /**
     * Gets a product variant by id.
     * @param sku - The unique stock keeping unit used to identify the product variant.
     * @param config - query config object for variant retrieval.
     * @return the product document.
     */
    retrieveBySKU(sku: string, config?: FindConfig<ProductVariant> & PriceSelectionContext): Promise<ProductVariant>;
    /**
     * Creates an unpublished product variant. Will validate against parent product
     * to ensure that the variant can in fact be created.
     * @param productOrProductId - the product the variant will be added to
     * @param variant - the variant to create
     * @return resolves to the creation result.
     */
    create(productOrProductId: string | Product, variant: CreateProductVariantInput): Promise<ProductVariant>;
    /**
     * Updates a variant.
     * Price updates should use dedicated methods.
     * The function will throw, if price updates are attempted.
     * @param variantOrVariantId - variant or id of a variant.
     * @param update - an object with the update values.
     * @param config - an object with the config values for returning the variant.
     * @return resolves to the update result.
     */
    update(variantOrVariantId: string | Partial<ProductVariant>, update: UpdateProductVariantInput): Promise<ProductVariant>;
    /**
     * Updates a variant's prices.
     * Deletes any prices that are not in the update object, and is not associated with a price list.
     * @param variantId - the id of variant
     * @param prices - the update prices
     * @returns empty promise
     */
    updateVariantPrices(variantId: string, prices: ProductVariantPrice[]): Promise<void>;
    /**
     * Gets the price specific to a region. If no region specific money amount
     * exists the function will try to use a currency price. If no default
     * currency price exists the function will throw an error.
     * @param variantId - the id of the variant to get price from
     * @param context - context for getting region price
     * @return the price specific to the region
     */
    getRegionPrice(variantId: string, context: GetRegionPriceContext): Promise<number | null>;
    /**
     * Sets the default price of a specific region
     * @param variantId - the id of the variant to update
     * @param price - the price for the variant.
     * @return the result of the update operation
     */
    setRegionPrice(variantId: string, price: ProductVariantPrice): Promise<MoneyAmount>;
    /**
     * Sets the default price for the given currency.
     * @param variantId - the id of the variant to set prices for
     * @param price - the price for the variant
     * @return the result of the update operation
     */
    setCurrencyPrice(variantId: string, price: ProductVariantPrice): Promise<MoneyAmount>;
    /**
     * Updates variant's option value.
     * Option value must be of type string or number.
     * @param variantId - the variant to decorate.
     * @param optionId - the option from product.
     * @param optionValue - option value to add.
     * @return the result of the update operation.
     */
    updateOptionValue(variantId: string, optionId: string, optionValue: string): Promise<ProductOptionValue>;
    /**
     * Adds option value to a variant.
     * Fails when product with variant does not exist or
     * if that product does not have an option with the given
     * option id. Fails if given variant is not found.
     * Option value must be of type string or number.
     * @param variantId - the variant to decorate.
     * @param optionId - the option from product.
     * @param optionValue - option value to add.
     * @return the result of the update operation.
     */
    addOptionValue(variantId: string, optionId: string, optionValue: string): Promise<ProductOptionValue>;
    /**
     * Deletes option value from given variant.
     * Will never fail due to delete being idempotent.
     * @param variantId - the variant to decorate.
     * @param optionId - the option from product.
     * @return empty promise
     */
    deleteOptionValue(variantId: string, optionId: string): Promise<void>;
    /**
     * @param selector - the query object for find
     * @param config - query config object for variant retrieval
     * @return the result of the find operation
     */
    listAndCount(selector: FilterableProductVariantProps, config?: FindConfig<ProductVariant> & PriceSelectionContext): Promise<[ProductVariant[], number]>;
    /**
     * @param selector - the query object for find
     * @param config - query config object for variant retrieval
     * @return the result of the find operation
     */
    list(selector: FilterableProductVariantProps, config?: FindConfig<ProductVariant> & PriceSelectionContext): Promise<ProductVariant[]>;
    /**
     * Deletes variant.
     * Will never fail due to delete being idempotent.
     * @param variantId - the id of the variant to delete. Must be
     *   castable as an ObjectId
     * @return empty promise
     */
    delete(variantId: string): Promise<void>;
    /**
     * Creates a query object to be used for list queries.
     * @param selector - the selector to create the query from
     * @param config - the config to use for the query
     * @return an object containing the query, relations and free-text
     *   search param.
     */
    prepareListQuery_(selector: FilterableProductVariantProps, config: FindConfig<ProductVariant>): {
        query: FindWithRelationsOptions;
        relations: string[];
        q?: string;
    };
    /**
     * Lists variants based on the provided parameters and includes the count of
     * variants that match the query.
     * @param variantRepo - the variant repository
     * @param query - object that defines the scope for what should be returned
     * @param q - free text query
     * @return an array containing the products as the first element and the total
     *   count of products that matches the query as the second element.
     */
    getFreeTextQueryBuilder_(variantRepo: ProductVariantRepository, query: FindWithRelationsOptions, q?: string): SelectQueryBuilder<ProductVariant>;
}
export default ProductVariantService;
