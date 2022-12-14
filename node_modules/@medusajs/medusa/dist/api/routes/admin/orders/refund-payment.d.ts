/**
 * @oas [post] /orders/{id}/refund
 * operationId: "PostOrdersOrderRefunds"
 * summary: "Create a Refund"
 * description: "Issues a Refund."
 * x-authenticated: true
 * parameters:
 *   - (path) id=* {string} The ID of the Order.
 * requestBody:
 *   content:
 *     application/json:
 *       schema:
 *         required:
 *           - amount
 *           - reason
 *         properties:
 *           amount:
 *             description: The amount to refund.
 *             type: integer
 *           reason:
 *             description: The reason for the Refund.
 *             type: string
 *           note:
 *             description: A note with additional details about the Refund.
 *             type: string
 *           no_notification:
 *             description: If set to true no notification will be send related to this Refund.
 *             type: boolean
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       // must be previously logged in or use api token
 *       medusa.admin.orders.refundPayment(order_id, {
 *         amount: 1000,
 *         reason: 'Do not like it'
 *       })
 *       .then(({ order }) => {
 *         console.log(order.id);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/admin/orders/adasda/refund' \
 *       --header 'Authorization: Bearer {api_token}' \
 *       --header 'Content-Type: application/json' \
 *       --data-raw '{
 *           "amount": 1000,
 *           "reason": "Do not like it"
 *       }'
 * security:
 *   - api_token: []
 *   - cookie_auth: []
 * tags:
 *   - Order
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
export declare class AdminPostOrdersOrderRefundsReq {
    amount: number;
    reason: string;
    note?: string;
    no_notification?: boolean;
}
