import { EntityManager } from "typeorm";
import { DeepPartial } from "typeorm/common/DeepPartial";
import { CartRepository } from "../repositories/cart";
import { LineItemRepository } from "../repositories/line-item";
import { LineItemTaxLineRepository } from "../repositories/line-item-tax-line";
import { Cart, LineItem, LineItemTaxLine } from "../models";
import { FindConfig, Selector } from "../types/common";
import { FlagRouter } from "../utils/flag-router";
import LineItemAdjustmentService from "./line-item-adjustment";
import { PricingService, ProductService, ProductVariantService, RegionService, TaxProviderService } from "./index";
import { TransactionBaseService } from "../interfaces";
declare type InjectedDependencies = {
    manager: EntityManager;
    lineItemRepository: typeof LineItemRepository;
    lineItemTaxLineRepository: typeof LineItemTaxLineRepository;
    cartRepository: typeof CartRepository;
    productVariantService: ProductVariantService;
    productService: ProductService;
    pricingService: PricingService;
    regionService: RegionService;
    lineItemAdjustmentService: LineItemAdjustmentService;
    taxProviderService: TaxProviderService;
    featureFlagRouter: FlagRouter;
};
declare class LineItemService extends TransactionBaseService {
    protected manager_: EntityManager;
    protected transactionManager_: EntityManager | undefined;
    protected readonly lineItemRepository_: typeof LineItemRepository;
    protected readonly itemTaxLineRepo_: typeof LineItemTaxLineRepository;
    protected readonly cartRepository_: typeof CartRepository;
    protected readonly productVariantService_: ProductVariantService;
    protected readonly productService_: ProductService;
    protected readonly pricingService_: PricingService;
    protected readonly regionService_: RegionService;
    protected readonly featureFlagRouter_: FlagRouter;
    protected readonly lineItemAdjustmentService_: LineItemAdjustmentService;
    protected readonly taxProviderService_: TaxProviderService;
    constructor({ manager, lineItemRepository, lineItemTaxLineRepository, productVariantService, productService, pricingService, regionService, cartRepository, lineItemAdjustmentService, taxProviderService, featureFlagRouter, }: InjectedDependencies);
    list(selector: Selector<LineItem>, config?: FindConfig<LineItem>): Promise<LineItem[]>;
    /**
     * Retrieves a line item by its id.
     * @param id - the id of the line item to retrieve
     * @param config - the config to be used at query building
     * @return the line item
     */
    retrieve(id: string, config?: {}): Promise<LineItem | never>;
    /**
     * Creates return line items for a given cart based on the return items in a
     * return.
     * @param returnId - the id to generate return items from.
     * @param cartId - the cart to assign the return line items to.
     * @return the created line items
     */
    createReturnLines(returnId: string, cartId: string): Promise<LineItem[]>;
    generate(variantId: string, regionId: string, quantity: number, context?: {
        unit_price?: number;
        includes_tax?: boolean;
        metadata?: Record<string, unknown>;
        customer_id?: string;
        order_edit_id?: string;
        cart?: Cart;
    }): Promise<LineItem>;
    /**
     * Create a line item
     * @param data - the line item object to create
     * @return the created line item
     */
    create(data: Partial<LineItem>): Promise<LineItem>;
    /**
     * Updates a line item
     * @param idOrSelector - the id or selector of the line item(s) to update
     * @param data - the properties to update the line item(s)
     * @return the updated line item(s)
     */
    update(idOrSelector: string | Selector<LineItem>, data: Partial<LineItem>): Promise<LineItem[]>;
    /**
     * Deletes a line item.
     * @param id - the id of the line item to delete
     * @return the result of the delete operation
     */
    delete(id: string): Promise<LineItem | undefined>;
    /**
     * Deletes a line item with the tax lines.
     * @param id - the id of the line item to delete
     * @return the result of the delete operation
     */
    deleteWithTaxLines(id: string): Promise<LineItem | undefined>;
    /**
     * Create a line item tax line.
     * @param args - tax line partial passed to the repo create method
     * @return a new line item tax line
     */
    createTaxLine(args: DeepPartial<LineItemTaxLine>): LineItemTaxLine;
    cloneTo(ids: string | string[], data?: DeepPartial<LineItem>, options?: {
        setOriginalLineItemId?: boolean;
    }): Promise<LineItem[]>;
}
export default LineItemService;
