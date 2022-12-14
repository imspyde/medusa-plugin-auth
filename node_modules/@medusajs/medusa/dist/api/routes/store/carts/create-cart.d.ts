/**
 * @oas [post] /carts
 * summary: "Create a Cart"
 * operationId: "PostCart"
 * description: "Creates a Cart within the given region and with the initial items. If no
 *   `region_id` is provided the cart will be associated with the first Region
 *   available. If no items are provided the cart will be empty after creation.
 *   If a user is logged in the cart's customer id and email will be set."
 * requestBody:
 *   content:
 *     application/json:
 *       schema:
 *         properties:
 *           region_id:
 *             type: string
 *             description: The ID of the Region to create the Cart in.
 *           sales_channel_id:
 *             type: string
 *             description: "[EXPERIMENTAL] The ID of the Sales channel to create the Cart in."
 *           country_code:
 *             type: string
 *             description: "The 2 character ISO country code to create the Cart in."
 *             externalDocs:
 *              url: https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2#Officially_assigned_code_elements
 *              description: See a list of codes.
 *           items:
 *             description: "An optional array of `variant_id`, `quantity` pairs to generate Line Items from."
 *             type: array
 *             items:
 *               required:
 *                 - variant_id
 *                 - quantity
 *               properties:
 *                 variant_id:
 *                   description: The id of the Product Variant to generate a Line Item from.
 *                   type: string
 *                 quantity:
 *                   description: The quantity of the Product Variant to add
 *                   type: integer
 *           context:
 *             description: "An optional object to provide context to the Cart. The `context` field is automatically populated with `ip` and `user_agent`"
 *             type: object
 *             example:
 *               ip: "::1"
 *               user_agent: "Chrome"
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       medusa.carts.create()
 *       .then(({ cart }) => {
 *         console.log(cart.id);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/store/carts'
 * tags:
 *   - Cart
 * responses:
 *   200:
 *     description: "Successfully created a new Cart"
 *     content:
 *       application/json:
 *         schema:
 *           properties:
 *             cart:
 *               $ref: "#/components/schemas/cart"
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
export declare class Item {
    variant_id: string;
    quantity: number;
}
export declare class StorePostCartReq {
    region_id?: string;
    country_code?: string;
    items?: Item[];
    context?: object;
    sales_channel_id?: string;
}
