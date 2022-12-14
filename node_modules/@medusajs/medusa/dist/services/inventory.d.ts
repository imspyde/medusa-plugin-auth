import { TransactionBaseService } from "../interfaces";
import { EntityManager } from "typeorm";
import ProductVariantService from "./product-variant";
import { ProductVariant } from "../models";
declare type InventoryServiceProps = {
    manager: EntityManager;
    productVariantService: ProductVariantService;
};
declare class InventoryService extends TransactionBaseService {
    protected readonly productVariantService_: ProductVariantService;
    protected manager_: EntityManager;
    protected transactionManager_: EntityManager | undefined;
    constructor({ manager, productVariantService }: InventoryServiceProps);
    /**
     * Updates the inventory of a variant based on a given adjustment.
     * @param variantId - the id of the variant to update
     * @param adjustment - the number to adjust the inventory quantity by
     * @return resolves to the update result.
     */
    adjustInventory(variantId: string, adjustment: number): Promise<ProductVariant | undefined>;
    /**
     * Checks if the inventory of a variant can cover a given quantity. Will
     * return true if the variant doesn't have managed inventory or if the variant
     * allows backorders or if the inventory quantity is greater than `quantity`.
     * @param variantId - the id of the variant to check
     * @param quantity - the number of units to check availability for
     * @return true if the inventory covers the quantity
     */
    confirmInventory(variantId: string | undefined | null, quantity: number): Promise<boolean>;
}
export default InventoryService;
