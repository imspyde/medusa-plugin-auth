/**
 * @oas [post] /carts/{id}/line-items
 * operationId: PostCartsCartLineItems
 * summary: "Add a Line Item"
 * description: "Generates a Line Item with a given Product Variant and adds it
 *   to the Cart"
 * parameters:
 *   - (path) id=* {string} The id of the Cart to add the Line Item to.
 *   - (body) variant_id=* {string} The id of the Product Variant to generate the Line Item from.
 *   - (body) quantity=* {integer} The quantity of the Product Variant to add to the Line Item.
 *   - (body) metadata {object} An optional key-value map with additional details about the Line Item.
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       medusa.carts.lineItems.create(cart_id, {
 *         variant_id,
 *         quantity: 1
 *       })
 *       .then(({ cart }) => {
 *         console.log(cart.id);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/store/carts/{id}/line-items' \
 *       --header 'Content-Type: application/json' \
 *       --data-raw '{
 *           "variant_id": "{variant_id}",
 *           "quantity": 1
 *       }'
 * tags:
 *   - Cart
 * responses:
 *   200:
 *     description: OK
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
export declare class StorePostCartsCartLineItemsReq {
    variant_id: string;
    quantity: number;
    metadata?: Record<string, unknown> | undefined;
}
