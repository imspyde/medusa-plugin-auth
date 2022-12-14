/**
 * @oas [post] /gift-cards
 * operationId: "PostGiftCards"
 * summary: "Create a Gift Card"
 * description: "Creates a Gift Card that can redeemed by its unique code. The Gift Card is only valid within 1 region."
 * x-authenticated: true
 * requestBody:
 *   content:
 *     application/json:
 *       schema:
 *         required:
 *           - region_id
 *         properties:
 *           value:
 *             type: integer
 *             description: The value (excluding VAT) that the Gift Card should represent.
 *           is_disabled:
 *             type: boolean
 *             description: Whether the Gift Card is disabled on creation. You will have to enable it later to make it available to Customers.
 *           ends_at:
 *             type: string
 *             format: date-time
 *             description: The time at which the Gift Card should no longer be available.
 *           region_id:
 *             description: The ID of the Region in which the Gift Card can be used.
 *             type: string
 *           metadata:
 *             description: An optional set of key-value pairs to hold additional information.
 *             type: object
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       // must be previously logged in or use api token
 *       medusa.admin.giftCards.create({
 *         region_id
 *       })
 *       .then(({ gift_card }) => {
 *         console.log(gift_card.id);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/admin/gift-cards' \
 *       --header 'Authorization: Bearer {api_token}' \
 *       --header 'Content-Type: application/json' \
 *       --data-raw '{
 *           "region_id": "{region_id}"
 *       }'
 * security:
 *   - api_token: []
 *   - cookie_auth: []
 * tags:
 *   - Gift Card
 * responses:
 *   200:
 *     description: OK
 *     content:
 *       application/json:
 *         schema:
 *           properties:
 *             gift_card:
 *               $ref: "#/components/schemas/gift_card"
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
export declare class AdminPostGiftCardsReq {
    value?: number;
    ends_at?: Date;
    is_disabled?: boolean;
    region_id: string;
    metadata?: Record<string, unknown>;
}
