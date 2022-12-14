/**
 * @oas [post] /swaps
 * operationId: PostSwaps
 * summary: Create a Swap
 * description: "Creates a Swap on an Order by providing some items to return along with some items to send back"
 * requestBody:
 *   content:
 *     application/json:
 *       schema:
 *         required:
 *           - order_id
 *           - return_items
 *           - additional_items
 *         properties:
 *           order_id:
 *             type: string
 *             description: The ID of the Order to create the Swap for.
 *           return_items:
 *             description: "The items to include in the Return."
 *             type: array
 *             items:
 *               required:
 *                 - item_id
 *                 - quantity
 *               properties:
 *                 item_id:
 *                   description: The ID of the Line Item from the Order.
 *                   type: string
 *                 quantity:
 *                   description: The quantity to swap.
 *                   type: integer
 *                 reason_id:
 *                   description: The ID of the reason of this return.
 *                   type: string
 *                 note:
 *                   description: The note to add to the item being swapped.
 *                   type: string
 *           return_shipping_option:
 *             type: string
 *             description: The ID of the Shipping Option to create the Shipping Method from.
 *           additional_items:
 *             description: "The items to exchange the returned items to."
 *             type: array
 *             items:
 *               required:
 *                 - variant_id
 *                 - quantity
 *               properties:
 *                 variant_id:
 *                   description: The ID of the Product Variant to send.
 *                   type: string
 *                 quantity:
 *                   description: The quantity to send of the variant.
 *                   type: integer
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       medusa.swaps.create({
 *         order_id,
 *         return_items: [
 *           {
 *             item_id,
 *             quantity: 1
 *           }
 *         ],
 *         additional_items: [
 *           {
 *             variant_id,
 *             quantity: 1
 *           }
 *         ]
 *       })
 *       .then(({ swap }) => {
 *         console.log(swap.id);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/store/swaps' \
 *       --header 'Content-Type: application/json' \
 *       --data-raw '{
 *           "order_id": "asfasf",
 *           "return_items": [
 *             {
 *               "item_id": "asfas",
 *               "quantity": 1
 *             }
 *           ],
 *           "additional_items": [
 *             {
 *               "variant_id": "asfas",
 *               "quantity": 1
 *             }
 *           ]
 *       }'
 * tags:
 *   - Swap
 * responses:
 *   200:
 *     description: OK
 *     content:
 *       application/json:
 *         schema:
 *           properties:
 *             swap:
 *               $ref: "#/components/schemas/swap"
 *   "400":
 *     $ref: "#/components/responses/400_error"
 *   "404":
 *     $ref: "#/components/responses/not_found_error"
 *   "409":
 *     $ref: "#/components/responses/invalid_state_error"
 *   "422":
 *     $ref: "#/components/responses/invalid_request_error"
 *   "500":
 *     $ref: "#/components/responses/500_error"
 */
declare const _default: (req: any, res: any) => Promise<void>;
export default _default;
declare class Item {
    item_id: string;
    quantity: number;
    reason_id?: string;
    note?: string;
}
declare class AdditionalItem {
    variant_id: string;
    quantity: number;
}
export declare class StorePostSwapsReq {
    order_id: string;
    return_items: Item[];
    additional_items: AdditionalItem[];
    return_shipping_option?: string;
}
