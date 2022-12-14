import { EntityManager } from "typeorm";
import { AbstractPriceSelectionStrategy, IPriceSelectionStrategy, PriceSelectionContext, PriceSelectionResult } from "../interfaces/price-selection-strategy";
declare class PriceSelectionStrategy extends AbstractPriceSelectionStrategy {
    private moneyAmountRepository_;
    private featureFlagRouter_;
    private manager_;
    constructor({ manager, featureFlagRouter, moneyAmountRepository }: {
        manager: any;
        featureFlagRouter: any;
        moneyAmountRepository: any;
    });
    withTransaction(manager: EntityManager): IPriceSelectionStrategy;
    calculateVariantPrice(variant_id: string, context: PriceSelectionContext): Promise<PriceSelectionResult>;
    private calculateVariantPrice_new;
    private calculateVariantPrice_old;
}
export default PriceSelectionStrategy;
