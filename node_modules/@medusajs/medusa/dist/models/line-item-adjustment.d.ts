import { Discount } from "./discount";
import { LineItem } from "./line-item";
export declare class LineItemAdjustment {
    id: string;
    item_id: string;
    item: LineItem;
    description: string;
    discount: Discount;
    discount_id: string;
    amount: number;
    metadata: Record<string, unknown>;
    private beforeInsert;
}
/**
 * @schema line_item_adjustment
 * title: "Line Item Adjustment"
 * description: "Represents an Line Item Adjustment"
 * x-resourceId: line_item_adjustment
 * required:
 *   - item_id
 *   - description
 *   - amount
 * properties:
 *   id:
 *     type: string
 *     description: The invite's ID
 *     example: lia_01G8TKE4XYCTHSCK2GDEP47RE1
 *   item_id:
 *     type: string
 *     description: The ID of the line item
 *     example: item_01G8ZC9GWT6B2GP5FSXRXNFNGN
 *   item:
 *     description: Available if the relation `item` is expanded.
 *     $ref: "#/components/schemas/line_item"
 *   description:
 *     type: string
 *     description: The line item's adjustment description
 *     example: Adjusted item's price.
 *   discount_id:
 *     type: string
 *     description: The ID of the discount associated with the adjustment
 *     example: disc_01F0YESMW10MGHWJKZSDDMN0VN
 *   discount:
 *     description: Available if the relation `discount` is expanded.
 *     $ref: "#/components/schemas/discount"
 *   amount:
 *     type: number
 *     description: The adjustment amount
 *     example: 1000
 *   metadata:
 *     type: object
 *     description: An optional key-value map with additional details
 *     example: {car: "white"}
 */
