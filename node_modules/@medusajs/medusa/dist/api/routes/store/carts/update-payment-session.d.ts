/**
 * @oas [post] /carts/{id}/payment-sessions/{provider_id}
 * operationId: PostCartsCartPaymentSessionUpdate
 * summary: Update a Payment Session
 * description: "Updates a Payment Session with additional data."
 * parameters:
 *   - (path) id=* {string} The id of the Cart.
 *   - (path) provider_id=* {string} The id of the payment provider.
 *   - (body) data=* {object} The data to update the payment session with.
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       medusa.carts.updatePaymentSession(cart_id, 'manual', {
 *         data: {
 *
 *         }
 *       })
 *       .then(({ cart }) => {
 *         console.log(cart.id);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/store/carts/{id}/payment-sessions/manual' \
 *       --header 'Content-Type: application/json' \
 *       --data-raw '{
 *           "data": {}
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
export declare class StorePostCartsCartPaymentSessionUpdateReq {
    data: Record<string, unknown>;
}
