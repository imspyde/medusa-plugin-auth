/**
 * @oas [post] /order/{id}/swaps
 * operationId: "PostOrdersOrderSwaps"
 * summary: "Create a Swap"
 * description: "Creates a Swap. Swaps are used to handle Return of previously purchased goods and Fulfillment of replacements simultaneously."
 * x-authenticated: true
 * parameters:
 *   - (path) id=* {string} The ID of the Order.
 * requestBody:
 *   content:
 *     application/json:
 *       schema:
 *         required:
 *           - return_items
 *         properties:
 *           return_items:
 *             description: The Line Items to return as part of the Swap.
 *             type: array
 *             items:
 *               required:
 *                 - item_id
 *                 - quantity
 *               properties:
 *                 item_id:
 *                   description: The ID of the Line Item that will be claimed.
 *                   type: string
 *                 quantity:
 *                   description: The number of items that will be returned
 *                   type: integer
 *                 reason_id:
 *                   description: The ID of the Return Reason to use.
 *                   type: string
 *                 note:
 *                   description: An optional note with information about the Return.
 *                   type: string
 *           return_shipping:
 *             description: How the Swap will be returned.
 *             type: object
 *             required:
 *               - option_id
 *             properties:
 *               option_id:
 *                 type: string
 *                 description: The ID of the Shipping Option to create the Shipping Method from.
 *               price:
 *                 type: integer
 *                 description: The price to charge for the Shipping Method.
 *           additional_items:
 *             description: The new items to send to the Customer.
 *             type: array
 *             items:
 *               required:
 *                 - variant_id
 *                 - quantity
 *               properties:
 *                 variant_id:
 *                   description: The ID of the Product Variant to ship.
 *                   type: string
 *                 quantity:
 *                   description: The quantity of the Product Variant to ship.
 *                   type: integer
 *           custom_shipping_options:
 *             description: The custom shipping options to potentially create a Shipping Method from.
 *             type: array
 *             items:
 *               required:
 *                 - option_id
 *                 - price
 *               properties:
 *                 option_id:
 *                   description: The ID of the Shipping Option to override with a custom price.
 *                   type: string
 *                 price:
 *                   description: The custom price of the Shipping Option.
 *                   type: integer
 *           no_notification:
 *             description: If set to true no notification will be send related to this Swap.
 *             type: boolean
 *           allow_backorder:
 *             description: If true, swaps can be completed with items out of stock
 *             type: boolean
 *             default: true
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       // must be previously logged in or use api token
 *       medusa.admin.orders.createSwap(order_id, {
 *         return_items: [
 *           {
 *             item_id,
 *             quantity: 1
 *           }
 *         ]
 *       })
 *       .then(({ order }) => {
 *         console.log(order.id);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/admin/orders/{id}/swaps' \
 *       --header 'Authorization: Bearer {api_token}' \
 *       --header 'Content-Type: application/json' \
 *       --data-raw '{
 *           "return_items": [
 *             {
 *               "item_id": "asfasf",
 *               "quantity": 1
 *             }
 *           ]
 *       }'
 * security:
 *   - api_token: []
 *   - cookie_auth: []
 * tags:
 *   - Swap
 * responses:
 *   200:
 *     description: OK
 *     content:
 *       application/json:
 *         schema:
 *           properties:
 *             order:
 *               $ref: "#/components/schemas/order"
 *   "400":
 *     $ref: "#/components/responses/400_error"
 *   "401":
 *     $ref: "#/components/responses/unauthorized"
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
export declare class AdminPostOrdersOrderSwapsReq {
    return_items: ReturnItem[];
    return_shipping?: ReturnShipping;
    additional_items?: AdditionalItem[];
    custom_shipping_options?: CustomShippingOption[];
    no_notification?: boolean;
    allow_backorder?: boolean;
}
declare class ReturnItem {
    item_id: string;
    quantity: number;
    reason_id?: string;
    note?: string;
}
declare class ReturnShipping {
    option_id: string;
    price?: number;
}
declare class CustomShippingOption {
    option_id: string;
    price: number;
}
declare class AdditionalItem {
    variant_id: string;
    quantity: number;
}
